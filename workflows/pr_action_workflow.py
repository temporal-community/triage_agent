import asyncio
import hashlib
import json
from datetime import timedelta
from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.workflow import ParentClosePolicy

with workflow.unsafe.imports_passed_through():
    from activities.models import PRContext, PRFilesSignals, RepoConfig, Verdict
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
        self._approver: str = ""

    @workflow.signal
    def submit_decision(self, decision: str, approver: str = "") -> None:
        """Send 'approve' to merge, anything else to reject.

        approver should be the GitHub username of the person making the decision.
        The workflow validates it against config.reviewers before honoring it.
        Setting approver is not cryptographically enforced (anyone who can reach
        Temporal can claim any username) — the proper fix is to source this signal
        exclusively from HMAC-verified GitHub webhook review events.
        """
        self._human_decision = decision
        self._approver = approver

    @workflow.query
    def status(self) -> dict:
        return {
            "awaiting_human": self._human_decision is None,
            "human_decision": self._human_decision,
            "approver": self._approver,
        }

    @workflow.run
    async def run(self, pr: PRContext) -> str:
        retry = RetryPolicy(maximum_attempts=5, initial_interval=timedelta(seconds=2))
        opts: dict = dict(
            start_to_close_timeout=timedelta(seconds=30),
            schedule_to_close_timeout=timedelta(minutes=5),
            retry_policy=retry,
        )

        config: RepoConfig = await workflow.execute_activity(
            "activities.platform.fetch_repo_config", pr, result_type=RepoConfig, **opts
        )

        # Cross-repo dedup: multiple repos seeing the same bump share one PackageTriageWorkflow.
        # The date suffix provides a 24-hour TTL — each UTC day produces a fresh verdict,
        # so a stale GREEN from yesterday cannot persist indefinitely. Within a day, all
        # repos seeing the same bump still share one triage run.
        #
        # Repos with extra_signal_activities get a fingerprint suffix so they dedup only
        # among repos with the same custom activity set; repos without custom activities
        # share the same workflow as before.
        #
        # check_pr_files runs in parallel: it's a fast per-PR check that looks for CI
        # workflows, Dockerfiles, or scripts in the PR — files that should never appear
        # in a routine dep-bump. No reason to block triage while waiting for it.
        date_key = workflow.now().strftime("%Y-%m-%d")
        extra_key = ""
        if config.extra_signal_activities:
            fp = hashlib.sha256(
                json.dumps(sorted(config.extra_signal_activities)).encode()
            ).hexdigest()[:8]
            extra_key = f"-x{fp}"
        verdict, pr_files = await asyncio.gather(
            workflow.execute_child_workflow(
                PackageTriageWorkflow.run,
                args=[
                    pr.ecosystem,
                    pr.package_name,
                    pr.old_version,
                    pr.new_version,
                    config.extra_signal_activities,
                ],
                id=f"triage-{pr.ecosystem}-{pr.package_name}-{pr.new_version}-{date_key}{extra_key}",
                parent_close_policy=ParentClosePolicy.ABANDON,
                execution_timeout=timedelta(minutes=15),
                result_type=Verdict,
            ),
            workflow.execute_activity(
                "activities.platform.check_pr_files",
                pr,
                result_type=PRFilesSignals,
                **opts,
            ),
        )

        # Hard escalation: unexpected CI/infra/script files in a dep-bump PR override
        # the triage verdict. Package-level analysis can't see the consuming-repo PR diff;
        # this is the only place that check happens.
        if pr_files.unexpected_files:
            verdict = Verdict(
                classification="red",
                confidence=0.95,
                reasoning=(
                    "CRITICAL: Non-dependency files changed alongside this dependency bump — "
                    "possible supply chain attack or repository compromise."
                ),
                flags=[f"unexpected file in PR: {f}" for f in pr_files.unexpected_files]
                + verdict.flags,
                release_age_hours=verdict.release_age_hours,
            )

        # Hard gate: enforce min_release_age_hours per repo policy regardless of LLM verdict.
        # The shared PackageTriageWorkflow verdict may have been produced for a different repo
        # with a different age policy, or the LLM may have ignored the age signal.
        if (
            verdict.classification == "green"
            and verdict.release_age_hours is not None
            and verdict.release_age_hours < config.min_release_age_hours
        ):
            verdict = verdict.model_copy(
                update={
                    "classification": "yellow",
                    "flags": verdict.flags
                    + [
                        f"release too fresh: {verdict.release_age_hours:.0f}h "
                        f"< {config.min_release_age_hours}h minimum for this repo"
                    ],
                }
            )

        if (
            verdict.classification == "green"
            and verdict.new_dependency_count >= config.max_new_dependencies
        ):
            verdict = verdict.model_copy(
                update={
                    "classification": "yellow",
                    "flags": verdict.flags
                    + [
                        f"{verdict.new_dependency_count} new direct dependencies added "
                        f"(max_new_dependencies: {config.max_new_dependencies} for this repo)"
                    ],
                }
            )

        await workflow.execute_activity("activities.platform.comment", args=[pr, verdict], **opts)

        if verdict.classification in config.block_classifications:
            await workflow.execute_activity(
                "activities.platform.label", args=[pr, "supply-chain-suspicious"], **opts
            )
            reason = (
                f"Triage agent classified this as **{verdict.classification.upper()}**. "
                f"Reason: {', '.join(verdict.flags) or verdict.reasoning[:200]}"
            )
            await workflow.execute_activity(
                "activities.platform.close_pr", args=[pr, reason, True], **opts
            )
            return f"blocked-{verdict.classification}"

        if (
            config.auto_merge_enabled
            and verdict.classification in config.auto_merge_classifications
            and verdict.confidence >= config.auto_merge_min_confidence
        ):
            await workflow.execute_activity("activities.platform.merge_pr", args=[pr], **opts)
            return "auto-merged"

        if config.reviewers:
            await workflow.execute_activity(
                "activities.platform.request_review", args=[pr, config.reviewers], **opts
            )

            # Wait for a decision from an authorized reviewer (max 7 days).
            # Re-check authorization each time a signal arrives in case an
            # unauthorized signal arrived first.
            while True:
                decision_received = await workflow.wait_condition(
                    lambda: self._human_decision is not None,
                    timeout=timedelta(days=7),
                )
                if not decision_received:
                    workflow.logger.warning("Human review wait timed out after 7 days")
                    return "timed-out-awaiting-review"
                if not config.reviewers or self._approver in config.reviewers:
                    break
                # Unauthorized signal — log and keep waiting
                workflow.logger.warning(
                    f"submit_decision from '{self._approver}' who is not in "
                    f"config.reviewers {config.reviewers} — ignoring"
                )
                self._human_decision = None
                self._approver = ""

            if self._human_decision == "approve":
                await workflow.execute_activity("activities.platform.merge_pr", args=[pr], **opts)
                return "human-approved-merged"
            return "human-rejected"

        # Default observe-only: comment posted, no further action.
        return f"observe-only-{verdict.classification}"
