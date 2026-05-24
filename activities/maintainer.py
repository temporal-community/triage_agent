from activities.ecosystems import get_provider
from activities.models import MaintainerSignals
from temporalio import activity


@activity.defn(name="activities.maintainer.history")
async def history(
    ecosystem: str, package: str, old_version: str, new_version: str
) -> MaintainerSignals:
    return await get_provider(ecosystem).fetch_maintainer(package, old_version, new_version)
