import asyncio
from datetime import timedelta
from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from activities.models import (
        PackageSignals, Verdict,
        PyPISignals, SocketSignals, OSVSignals,
        DiffSignals, MaintainerSignals, ReleaseAgeSignals,
    )


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
    ) -> Verdict:
        retry = RetryPolicy(maximum_attempts=5, initial_interval=timedelta(seconds=2))
        opts: dict = dict(start_to_close_timeout=timedelta(seconds=30), retry_policy=retry)
        args = [ecosystem, package, old_version, new_version]

        pypi, sock, osv, diff, maint, age = await asyncio.gather(
            workflow.execute_activity(
                "activities.pypi_metadata.fetch", args=args, result_type=PyPISignals, **opts
            ),
            workflow.execute_activity(
                "activities.socket.score", args=args, result_type=SocketSignals, **opts
            ),
            workflow.execute_activity(
                "activities.osv.check", args=args, result_type=OSVSignals, **opts
            ),
            workflow.execute_activity(
                "activities.package_diff.compute",
                args=args,
                result_type=DiffSignals,
                start_to_close_timeout=timedelta(minutes=2),
                retry_policy=retry,
            ),
            workflow.execute_activity(
                "activities.maintainer.history", args=args, result_type=MaintainerSignals, **opts
            ),
            workflow.execute_activity(
                "activities.release_age.check", args=args, result_type=ReleaseAgeSignals, **opts
            ),
        )

        signals = PackageSignals(
            ecosystem=ecosystem,
            package_name=package,
            old_version=old_version,
            new_version=new_version,
            **pypi.model_dump(),
            **sock.model_dump(),
            **osv.model_dump(),
            **diff.model_dump(),
            **maint.model_dump(),
            **age.model_dump(),
        )

        return await workflow.execute_activity(
            "activities.classifier.classify",
            signals,
            result_type=Verdict,
            start_to_close_timeout=timedelta(seconds=60),
            retry_policy=retry,
        )
