"""Activity: fetch deprecation status from deps.dev (https://api.deps.dev)."""
from urllib.parse import quote

import httpx
from temporalio import activity

from activities.models import DepsDevSignals

_ECOSYSTEM_MAP = {"pip": "pypi", "npm": "npm", "rubygems": "rubygems"}


@activity.defn(name="activities.depsdev.fetch")
async def fetch(ecosystem: str, package: str, old_version: str, new_version: str) -> DepsDevSignals:
    system = _ECOSYSTEM_MAP.get(ecosystem)
    if system is None:
        return DepsDevSignals()

    encoded_package = quote(package, safe="")
    encoded_version = quote(new_version, safe="")
    url = f"https://api.deps.dev/v3alpha/systems/{system}/packages/{encoded_package}/versions/{encoded_version}"

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(url)

        if resp.status_code != 200:
            return DepsDevSignals()

        data = resp.json()
        is_deprecated = data.get("isDeprecated", False)
        deprecated_reason = data.get("deprecatedReason") or None

        return DepsDevSignals(is_deprecated=is_deprecated, deprecated_reason=deprecated_reason)
    except Exception as exc:
        activity.logger.warning(f"deps.dev fetch failed for {package}@{new_version}: {exc!r}")
        return DepsDevSignals()
