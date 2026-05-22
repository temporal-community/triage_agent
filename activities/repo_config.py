from temporalio import activity
from activities.models import PRContext, RepoConfig


@activity.defn(name="activities.repo_config.fetch")
async def fetch(pr: PRContext) -> RepoConfig:
    activity.logger.info(f"[stub] Fetching repo config for {pr.repo} — returning defaults")
    return RepoConfig()
