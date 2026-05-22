from datetime import timedelta
from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.workflow import ParentClosePolicy

with workflow.unsafe.imports_passed_through():
    from activities.models import PRContext, RepoConfig, Verdict
    from workflows.package_triage_workflow import PackageTriageWorkflow


@workflow.defn
class PRActionWorkflow:
    """
    Per-PR action workflow. Fetches repo config, runs (or attaches to) PackageTriageWorkflow,
    and acts based on verdict + config: comment, auto-merge, request review, or escalate.

    Workflow ID: pr-action-{repo}-{pr_number}
    """

    def __init__(self) -> None:
        self._human_decision: str | None = None

    @workflow.signal
    def submit_decision(self, decision: str) -> None:
        """Send 'approve' to merge, anything else to reject."""
        self._human_decision = decision

    @workflow.query
    def status(self) -> dict:
        return {
            "awaiting_human": self._human_decision is None,
            "human_decision": self._human_decision,
        }

    @workflow.run
    async def run(self, pr: PRContext) -> str:
        retry = RetryPolicy(maximum_attempts=5, initial_interval=timedelta(seconds=2))
        opts: dict = dict(start_to_close_timeout=timedelta(seconds=30), retry_policy=retry)

        config: RepoConfig = await workflow.execute_activity(
            "activities.repo_config.fetch", pr, result_type=RepoConfig, **opts
        )

        # Cross-repo dedup: multiple repos seeing the same bump share one PackageTriageWorkflow.
        verdict: Verdict = await workflow.execute_child_workflow(
            PackageTriageWorkflow.run,
            args=[pr.ecosystem, pr.package_name, pr.old_version, pr.new_version],
            id=f"triage-{pr.ecosystem}-{pr.package_name}-{pr.new_version}",
            parent_close_policy=ParentClosePolicy.ABANDON,
            result_type=Verdict,
        )

        await workflow.execute_activity(
            "activities.github.comment", args=[pr, verdict], **opts
        )

        if verdict.classification in config.block_classifications:
            await workflow.execute_activity(
                "activities.github.label", args=[pr, "supply-chain-suspicious"], **opts
            )
            return f"blocked-{verdict.classification}"

        if (
            config.auto_merge_enabled
            and verdict.classification in config.auto_merge_classifications
        ):
            await workflow.execute_activity("activities.github.merge_pr", args=[pr], **opts)
            return "auto-merged"

        if config.reviewers:
            await workflow.execute_activity(
                "activities.github.request_review", args=[pr, config.reviewers], **opts
            )
            await workflow.wait_condition(lambda: self._human_decision is not None)
            if self._human_decision == "approve":
                await workflow.execute_activity(
                    "activities.github.merge_pr", args=[pr], **opts
                )
                return "human-approved-merged"
            return "human-rejected"

        # Default observe-only: comment posted, no further action.
        return f"observe-only-{verdict.classification}"
