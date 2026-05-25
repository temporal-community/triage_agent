import asyncio
from datetime import timedelta
from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from models import (
        CheckContext,
        PackageChecks,
        Verdict,
        MetadataChecks,
        SocketChecks,
        OSVChecks,
        PackageDiffChecks,
        MaintainerChecks,
        ReleaseAgeChecks,
        AttestationChecks,
        ReleaseChecks,
        VersionLineageChecks,
        DepsDevChecks,
        ScorecardChecks,
    )

# Single source of truth for check activities:
#   (PackageChecks field name, activity name string, result model, use slow timeout?)
#
# Adding a check: append one row here and add the sub-model to PackageChecks in models.py.
# The test in tests/test_check_wiring.py will catch if the worker registration is missing.
#
# Append-only: inserting mid-list changes Temporal's ScheduleActivity command sequence,
# which breaks replay of existing workflow histories and requires fixture regeneration.
_CHECK_REGISTRY: list[tuple[str, str, type, bool]] = [
    ("metadata", "activities.metadata.fetch", MetadataChecks, False),
    ("socket", "activities.socket.score", SocketChecks, False),
    ("osv", "activities.osv.check", OSVChecks, False),
    ("diff", "activities.package_diff.compute", PackageDiffChecks, True),  # archive download
    ("maintainer", "activities.maintainer.history", MaintainerChecks, False),
    ("age", "activities.release_age.check", ReleaseAgeChecks, False),
    ("attestation", "activities.attestation.check", AttestationChecks, False),
    ("release", "activities.release_notes.check", ReleaseChecks, False),
    ("version_lineage", "activities.version_lineage.check", VersionLineageChecks, False),
    ("deps_dev", "activities.depsdev.fetch", DepsDevChecks, False),
    ("scorecard", "activities.scorecard.fetch", ScorecardChecks, False),
]

# Derived from the registry — used by tests/test_check_wiring.py to verify worker registration.
# Includes the custom_checks runner which is always called even when no plugins are installed.
CHECK_ACTIVITY_NAMES: list[str] = [name for _, name, _, _ in _CHECK_REGISTRY] + [
    "activities.custom_checks.run_all"
]


@workflow.defn
class PackageTriageWorkflow:
    """
    Gathers supply chain checks in parallel and classifies risk with an LLM.

    Workflow ID: triage-{ecosystem}-{package}-{new_version}
    Reuse policy: REJECT_DUPLICATE — multiple repos seeing the same version bump
    share one triage run and its verdict.
    """

    @workflow.run
    async def run(
        self,
        ecosystem: str,
        package: str,
        old_version: str,
        new_version: str,
        extra_check_activities: list[str] = [],
    ) -> Verdict:
        retry = RetryPolicy(maximum_attempts=5, initial_interval=timedelta(seconds=2))
        default_opts: dict = dict(
            start_to_close_timeout=timedelta(seconds=30),
            schedule_to_close_timeout=timedelta(minutes=5),
            retry_policy=retry,
        )
        slow_opts: dict = dict(
            start_to_close_timeout=timedelta(minutes=2),
            schedule_to_close_timeout=timedelta(minutes=10),
            heartbeat_timeout=timedelta(seconds=45),  # detect stuck archive downloads
            retry_policy=retry,
        )
        args = [ecosystem, package, old_version, new_version]

        raw = await asyncio.gather(
            *(
                workflow.execute_activity(
                    name,
                    args=args,
                    result_type=model,
                    **(slow_opts if slow else default_opts),
                )
                for _, name, model, slow in _CHECK_REGISTRY
            ),
            return_exceptions=True,
        )

        # Map results by field name. A failed activity gets its model's degraded defaults
        # rather than propagating an exception that would discard all other check results.
        check_kwargs: dict[str, object] = {}
        for (field, _, model, _), result in zip(_CHECK_REGISTRY, raw):
            if isinstance(result, Exception):
                workflow.logger.warning(
                    f"Check '{field}' failed after retries: {result!r} — using degraded defaults"
                )
                check_kwargs[field] = model()
            else:
                check_kwargs[field] = result

        custom_checks_result = await workflow.execute_activity(
            "activities.custom_checks.run_all",
            CheckContext(
                package=package,
                ecosystem=ecosystem,
                old_version=old_version,
                new_version=new_version,
            ),
            result_type=dict,
            **default_opts,
        )

        if extra_check_activities:
            extra_raw = await asyncio.gather(
                *(
                    workflow.execute_activity(
                        name,
                        CheckContext(
                            package=package,
                            ecosystem=ecosystem,
                            old_version=old_version,
                            new_version=new_version,
                        ),
                        result_type=dict,
                        **default_opts,
                    )
                    for name in extra_check_activities
                ),
                return_exceptions=True,
            )
            for name, result in zip(extra_check_activities, extra_raw):
                if isinstance(result, Exception):
                    workflow.logger.warning(f"Activity check '{name}' failed: {result!r} — skipped")
                else:
                    custom_checks_result[name] = result

        package_checks = PackageChecks(
            ecosystem=ecosystem,
            package_name=package,
            old_version=old_version,
            new_version=new_version,
            custom_checks=custom_checks_result,
            **check_kwargs,  # type: ignore[arg-type]
        )

        return await workflow.execute_activity(
            "activities.classifier.classify",
            package_checks,
            result_type=Verdict,
            start_to_close_timeout=timedelta(seconds=60),
            retry_policy=retry,
        )
