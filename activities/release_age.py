from ecosystems import get_provider
from models import ReleaseAgeChecks
from helpers.cache import ActivityCache
from temporalio import activity

_cache: ActivityCache = ActivityCache()  # upload timestamps are immutable


@activity.defn(name="activities.release_age.check")
async def check(
    ecosystem: str, package: str, old_version: str, new_version: str
) -> ReleaseAgeChecks:
    """Look up when the new version was published to the registry and calculate how many hours ago that was.

    Returns a ``ReleaseAgeChecks`` with the age in hours; very recent releases (under ~24 hours) are a yellow signal."""
    key = (ecosystem, package, new_version)
    if (hit := _cache.get(key)) is not None:
        activity.logger.debug("release_age cache hit: %s %s", package, new_version)
        return hit
    result = await get_provider(ecosystem).fetch_release_age(package, new_version)
    _cache.set(key, result)
    return result
