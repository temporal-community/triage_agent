"""Fetch CVEs/advisories *fixed* by this version bump.

Queries OSV.dev for vulnerabilities that affect old_version but not new_version.
This provides universal context for all classifiers — if an upgrade fixes known CVEs,
that changes the risk calculus significantly (makes YELLOW or even RED more justified
for staying on the old version, and makes the new version more trustworthy).
"""

from temporalio import activity

from ecosystems import get_meta
from models import SecurityAdvisoryChecks
from helpers.cache import ActivityCache
from helpers.http import get_client

_cache: ActivityCache = ActivityCache(ttl_seconds=3600)


@activity.defn(name="activities.security_advisories.fetch")
async def fetch(
    ecosystem: str, package: str, old_version: str, new_version: str
) -> SecurityAdvisoryChecks:
    """Return CVEs/advisories present in old_version but absent in new_version.

    A non-empty result means this bump patches known vulnerabilities — important context
    for the classifier when weighing other risk signals like obfuscated code."""
    key = (ecosystem, package, old_version, new_version, "advisory")
    if (hit := _cache.get(key)) is not None:
        activity.logger.debug("advisory cache hit: %s %s→%s", package, old_version, new_version)
        return hit

    meta = get_meta(ecosystem)
    osv_ecosystem = meta.osv_name if meta else ""
    client = get_client()

    # Fetch all vulns affecting old_version
    old_resp = await client.post(
        "https://api.osv.dev/v1/query",
        json={"package": {"name": package, "ecosystem": osv_ecosystem}, "version": old_version},
        timeout=15.0,
    )
    old_resp.raise_for_status()

    # Fetch all vulns affecting new_version
    new_resp = await client.post(
        "https://api.osv.dev/v1/query",
        json={"package": {"name": package, "ecosystem": osv_ecosystem}, "version": new_version},
        timeout=15.0,
    )
    new_resp.raise_for_status()

    def _ids(data: dict) -> set[str]:
        ids: set[str] = set()
        for vuln in data.get("vulns", []):
            cves = [a for a in vuln.get("aliases", []) if a.startswith("CVE-")]
            ids.update(cves if cves else [vuln["id"]])
        return ids

    old_ids = _ids(old_resp.json())
    new_ids = _ids(new_resp.json())
    fixed_ids = sorted(old_ids - new_ids)

    if not fixed_ids:
        result = SecurityAdvisoryChecks()
        _cache.set(key, result)
        return result

    # Fetch brief summaries for fixed vulns
    summaries: list[str] = []
    severities: list[str] = []
    for vuln_id in fixed_ids[:10]:  # cap to avoid very long prompts
        try:
            detail_resp = await client.get(f"https://api.osv.dev/v1/vulns/{vuln_id}", timeout=10.0)
            if detail_resp.status_code == 200:
                detail = detail_resp.json()
                summary = detail.get("summary") or detail.get("details", "")[:200]
                summaries.append(summary[:200] if summary else "")
                # Severity: look for CVSS severity string
                sev = ""
                for s in detail.get("severity", []):
                    score_str = s.get("score", "")
                    if score_str.startswith("CVSS"):
                        # Extract severity from CVSS vector or use score field
                        pass
                # Try database_specific or affected[].ecosystem_specific
                for aff in detail.get("affected", []):
                    es = aff.get("ecosystem_specific", {})
                    sev = es.get("severity", "") or sev
                    ds = aff.get("database_specific", {})
                    sev = ds.get("severity", "") or sev
                severities.append(sev.upper() if sev else "")
            else:
                summaries.append("")
                severities.append("")
        except Exception:
            summaries.append("")
            severities.append("")

    result = SecurityAdvisoryChecks(
        fixed_vulnerabilities=fixed_ids,
        fixed_summaries=summaries,
        fixed_severity=severities,
    )
    _cache.set(key, result)
    activity.logger.info(
        "advisory: %s %s→%s fixes %d CVE(s): %s",
        package,
        old_version,
        new_version,
        len(fixed_ids),
        ", ".join(fixed_ids[:5]),
    )
    return result
