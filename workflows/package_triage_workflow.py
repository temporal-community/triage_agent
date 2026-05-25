import asyncio
from datetime import timedelta
from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from models import (
        PackageSignals,
        Verdict,
        PyPISignals,
        SocketSignals,
        OSVSignals,
        DiffSignals,
        MaintainerSignals,
        ReleaseAgeSignals,
        AttestationSignals,
        ReleaseSignals,
        VersionLineSignals,
        DepsDevSignals,
        ScorecardSignals,
    )

# Single source of truth for signal activities:
#   (PackageSignals field name, activity name string, result model, use slow timeout?)
#
# Adding a signal: append one row here and add the sub-model to PackageSignals in models.py.
# The test in tests/test_signal_wiring.py will catch if the worker registration is missing.
#
# Append-only: inserting mid-list changes Temporal's ScheduleActivity command sequence,
# which breaks replay of existing workflow histories and requires fixture regeneration.
_SIGNAL_REGISTRY: list[tuple[str, str, type, bool]] = [
    ("pypi", "activities.pypi_metadata.fetch", PyPISignals, False),
    ("socket", "activities.socket.score", SocketSignals, False),
    ("osv", "activities.osv.check", OSVSignals, False),
    ("diff", "activities.package_diff.compute", DiffSignals, True),  # archive download
    ("maintainer", "activities.maintainer.history", MaintainerSignals, False),
    ("age", "activities.release_age.check", ReleaseAgeSignals, False),
    ("attestation", "activities.attestation.check", AttestationSignals, False),
    ("release", "activities.release_notes.check", ReleaseSignals, False),
    ("version_line", "activities.version_lineage.check", VersionLineSignals, False),
    ("deps_dev", "activities.depsdev.fetch", DepsDevSignals, False),
    ("scorecard", "activities.scorecard.fetch", ScorecardSignals, False),
]

# Derived from the registry — used by tests/test_signal_wiring.py to verify worker registration.
SIGNAL_ACTIVITY_NAMES: list[str] = [name for _, name, _, _ in _SIGNAL_REGISTRY]


@workflow.defn
class PackageTriageWorkflow:
    """
    Gathers supply chain signals in parallel and classifies risk with an LLM.

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
        extra_signal_activities: list[str] = [],
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
                for _, name, model, slow in _SIGNAL_REGISTRY
            ),
            return_exceptions=True,
        )

        # Map results by field name. A failed activity gets its model's degraded defaults
        # rather than propagating an exception that would discard all other signal results.
        signal_kwargs: dict[str, object] = {}
        for (field, _, model, _), result in zip(_SIGNAL_REGISTRY, raw):
            if isinstance(result, Exception):
                workflow.logger.warning(
                    f"Signal '{field}' failed after retries: {result!r} — using degraded defaults"
                )
                signal_kwargs[field] = model()
            else:
                signal_kwargs[field] = result

        custom_signals: dict[str, object] = {}
        if extra_signal_activities:
            custom_raw = await asyncio.gather(
                *(
                    workflow.execute_activity(
                        name,
                        args=args,
                        result_type=dict,
                        **default_opts,
                    )
                    for name in extra_signal_activities
                ),
                return_exceptions=True,
            )
            for name, result in zip(extra_signal_activities, custom_raw):
                if isinstance(result, Exception):
                    workflow.logger.warning(f"Custom signal '{name}' failed: {result!r} — skipped")
                else:
                    custom_signals[name] = result

        signals = PackageSignals(
            ecosystem=ecosystem,
            package_name=package,
            old_version=old_version,
            new_version=new_version,
            custom_signals=custom_signals,
            **signal_kwargs,  # type: ignore[arg-type]
        )

        return await workflow.execute_activity(
            "activities.classifier.classify",
            signals,
            result_type=Verdict,
            start_to_close_timeout=timedelta(seconds=60),
            retry_policy=retry,
        )
