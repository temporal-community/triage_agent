import os

from temporalio import activity

from activities.models import PRContext, RepoConfig


@activity.defn(name="activities.repo_config.fetch")
async def fetch(pr: PRContext) -> RepoConfig:
    activity.logger.info(f"[stub] Fetching repo config for {pr.repo} — returning defaults")
    # FORCE_AUTO_MERGE=true in .env enables auto-merge for local testing
    # before real per-repo config fetching is wired up (Step 6).
    auto_merge = os.environ.get("FORCE_AUTO_MERGE", "false").lower() == "true"
    return RepoConfig(auto_merge_enabled=auto_merge)
