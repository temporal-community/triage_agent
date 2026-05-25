from activities.ecosystems import get_provider
from activities.models import AttestationSignals
from helpers.cache import ActivityCache
from temporalio import activity

_cache: ActivityCache = ActivityCache()  # SLSA provenance is immutable once signed


@activity.defn(name="activities.attestation.check")
async def check(
    ecosystem: str, package: str, old_version: str, new_version: str
) -> AttestationSignals:
    key = (ecosystem, package, old_version, new_version)
    if (hit := _cache.get(key)) is not None:
        activity.logger.debug("attestation cache hit: %s %s", package, new_version)
        return hit
    result = await get_provider(ecosystem).fetch_attestations(package, old_version, new_version)
    _cache.set(key, result)
    return result
