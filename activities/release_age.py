from ecosystems import get_provider
from models import ReleaseAgeSignals
from helpers.cache import ActivityCache
from temporalio import activity

_cache: ActivityCache = ActivityCache()  # upload timestamps are immutable


@activity.defn(name="activities.release_age.check")
async def check(
    ecosystem: str, package: str, old_version: str, new_version: str
) -> ReleaseAgeSignals:
    key = (ecosystem, package, new_version)
    if (hit := _cache.get(key)) is not None:
        activity.logger.debug("release_age cache hit: %s %s", package, new_version)
        return hit
    result = await get_provider(ecosystem).fetch_release_age(package, new_version)
    _cache.set(key, result)
    return result
