"""Activity: fetch deprecation status from deps.dev (https://api.deps.dev)."""

from urllib.parse import quote

from temporalio import activity

from models import DepsDevChecks
from helpers.cache import ActivityCache
from helpers.http import get_client

_cache: ActivityCache = ActivityCache(ttl_seconds=86400)  # deprecation changes rarely; 24h TTL

_ECOSYSTEM_MAP = {
    "pip": "pypi",
    "npm": "npm",
    "rubygems": "rubygems",
    "maven": "maven",
    "nuget": "nuget",
}


@activity.defn(name="activities.depsdev.fetch")
async def fetch(ecosystem: str, package: str, old_version: str, new_version: str) -> DepsDevChecks:
    key = (ecosystem, package, new_version)
    if (hit := _cache.get(key)) is not None:
        activity.logger.debug("depsdev cache hit: %s %s", package, new_version)
        return hit

    system = _ECOSYSTEM_MAP.get(ecosystem)
    if system is None:
        return DepsDevChecks()

    encoded_package = quote(package, safe="")
    encoded_version = quote(new_version, safe="")
    url = f"https://api.deps.dev/v3alpha/systems/{system}/packages/{encoded_package}/versions/{encoded_version}"

    try:
        client = get_client()
        resp = await client.get(url, timeout=15.0)

        if resp.status_code != 200:
            return DepsDevChecks()

        data = resp.json()
        is_deprecated = data.get("isDeprecated", False)
        deprecated_reason = data.get("deprecatedReason") or None

        result = DepsDevChecks(is_deprecated=is_deprecated, deprecated_reason=deprecated_reason)
        _cache.set(key, result)
        return result
    except Exception as exc:
        activity.logger.warning(f"deps.dev fetch failed for {package}@{new_version}: {exc!r}")
        return DepsDevChecks()
