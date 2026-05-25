from temporalio import activity

from ecosystems import get_provider
from models import OSVChecks
from helpers.cache import ActivityCache
from helpers.http import get_client

_cache: ActivityCache = ActivityCache(ttl_seconds=3600)  # new CVEs can appear; refresh hourly


@activity.defn(name="activities.osv.check")
async def check(ecosystem: str, package: str, old_version: str, new_version: str) -> OSVChecks:
    """Query the OSV.dev API to find published vulnerabilities affecting the new version of this package.

    Returns an ``OSVChecks`` containing a list of CVE or OSV IDs for any matching advisories."""
    key = (ecosystem, package, new_version)
    if (hit := _cache.get(key)) is not None:
        activity.logger.debug("osv cache hit: %s %s", package, new_version)
        return hit

    osv_ecosystem = get_provider(ecosystem).osv_name
    client = get_client()
    resp = await client.post(
        "https://api.osv.dev/v1/query",
        json={
            "package": {"name": package, "ecosystem": osv_ecosystem},
            "version": new_version,
        },
        timeout=15.0,
    )
    resp.raise_for_status()
    data = resp.json()

    vuln_ids: list[str] = []
    for vuln in data.get("vulns", []):
        cves = [a for a in vuln.get("aliases", []) if a.startswith("CVE-")]
        vuln_ids.extend(cves if cves else [vuln["id"]])

    result = OSVChecks(osv_vulnerabilities=vuln_ids)
    _cache.set(key, result)
    return result
