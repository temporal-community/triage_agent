from activities.ecosystems import get_provider
from activities.models import MaintainerSignals
from helpers.cache import ActivityCache
from temporalio import activity

_cache: ActivityCache = ActivityCache()  # publishing history is immutable


@activity.defn(name="activities.maintainer.history")
async def history(
    ecosystem: str, package: str, old_version: str, new_version: str
) -> MaintainerSignals:
    key = (ecosystem, package, old_version, new_version)
    if (hit := _cache.get(key)) is not None:
        activity.logger.debug("maintainer cache hit: %s %s", package, new_version)
        return hit
    result = await get_provider(ecosystem).fetch_maintainer(package, old_version, new_version)
    _cache.set(key, result)
    return result
