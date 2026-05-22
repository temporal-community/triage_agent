from temporalio import activity
from activities.models import MaintainerSignals


@activity.defn(name="activities.maintainer.history")
async def history(ecosystem: str, package: str, old_version: str, new_version: str) -> MaintainerSignals:
    activity.logger.info(f"[stub] Checking maintainer history for {package} {new_version}")
    return MaintainerSignals(maintainer_changed=False)
