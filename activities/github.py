from temporalio import activity
from activities.models import PRContext, Verdict


@activity.defn(name="activities.github.comment")
async def comment(pr: PRContext, verdict: Verdict) -> None:
    activity.logger.info(
        f"[stub] Would post comment on {pr.repo}#{pr.pr_number}: "
        f"{verdict.classification} ({verdict.confidence:.0%}) — {verdict.reasoning[:80]}"
    )


@activity.defn(name="activities.github.merge_pr")
async def merge_pr(pr: PRContext) -> None:
    activity.logger.info(f"[stub] Would squash-merge {pr.repo}#{pr.pr_number}")


@activity.defn(name="activities.github.request_review")
async def request_review(pr: PRContext, reviewers: list[str]) -> None:
    activity.logger.info(
        f"[stub] Would request review on {pr.repo}#{pr.pr_number} from {reviewers}"
    )


@activity.defn(name="activities.github.label")
async def label(pr: PRContext, label_name: str) -> None:
    activity.logger.info(
        f"[stub] Would add label '{label_name}' to {pr.repo}#{pr.pr_number}"
    )


@activity.defn(name="activities.github.get_pr")
async def get_pr(pr: PRContext) -> dict:
    activity.logger.info(f"[stub] Would fetch PR state for {pr.repo}#{pr.pr_number}")
    return {"state": "open", "mergeable": True, "checks_passed": True}
