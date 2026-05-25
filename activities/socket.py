import os

from temporalio import activity
from temporalio.exceptions import ApplicationError

from models import SocketSignals
from helpers.cache import ActivityCache
from helpers.http import get_client

_cache: ActivityCache = ActivityCache(ttl_seconds=3600)  # scores can be updated; refresh hourly

_ECOSYSTEM_MAP = {
    "pip": "pypi",
    "npm": "npm",
    "rubygems": "gem",
    "cargo": "cargo",
    "nuget": "nuget",
}
_INCLUDE_SEVERITIES = {"critical", "high"}

# Alert types significant enough to surface even at medium severity.
# Socket sometimes rates malware/obfuscation as "medium" on first detection.
_MEDIUM_INCLUDE_TYPES = {
    "malware",
    "protestware",
    "obfuscatedCode",
    "shellAccess",
    "networkAccess",
    "envVars",
    "installScripts",
    "dynamicRequire",
    "binScriptConfusion",
    "changedAuthor",
}


@activity.defn(name="activities.socket.score")
async def score(ecosystem: str, package: str, old_version: str, new_version: str) -> SocketSignals:
    key = (ecosystem, package, new_version)
    if (hit := _cache.get(key)) is not None:
        activity.logger.debug("socket cache hit: %s %s", package, new_version)
        return hit

    api_key = os.environ.get("SOCKET_API_KEY")
    if not api_key:
        activity.logger.info(
            "No SOCKET_API_KEY — skipping Socket score (treated as yellow indicator)"
        )
        return SocketSignals(socket_score=None, socket_alerts=[])

    ecosystem_slug = _ECOSYSTEM_MAP.get(ecosystem, "pypi")
    purl = f"pkg:{ecosystem_slug}/{package}@{new_version}"

    client = get_client()
    resp = await client.post(
        "https://api.socket.dev/v0/purl",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"components": [{"purl": purl}]},
        params={"alerts": "true"},
        timeout=15.0,
    )

    if resp.status_code == 401:
        raise ApplicationError(
            "Socket API auth failed — check SOCKET_API_KEY",
            non_retryable=True,
        )
    if resp.status_code == 404:
        activity.logger.info(f"{package}@{new_version} not found in Socket database")
        return SocketSignals(socket_score=None, socket_alerts=[])
    if resp.status_code == 429:
        raise ApplicationError("Socket API rate limited", non_retryable=False)

    resp.raise_for_status()

    packages = resp.json().get("packages", [])
    if not packages:
        return SocketSignals(socket_score=None, socket_alerts=[])

    pkg = packages[0]
    depscore = pkg.get("score", {}).get("depscore")
    socket_score = round(depscore * 100) if depscore is not None else None

    def _include(a: dict) -> bool:
        sev = a.get("severity", "")
        typ = a.get("type", "")
        return sev in _INCLUDE_SEVERITIES or (sev == "medium" and typ in _MEDIUM_INCLUDE_TYPES)

    included = [a for a in pkg.get("alerts", []) if _include(a)]
    alerts = [
        f"[{a['severity']}] {a.get('type', 'unknown')}: {a.get('message', '').strip()}"
        for a in included
    ]
    alert_types = list({a.get("type", "unknown") for a in included})

    activity.logger.info(
        f"Socket: {package}@{new_version} score={socket_score} alerts={len(alerts)}"
    )
    result = SocketSignals(
        socket_score=socket_score,
        socket_alerts=alerts,
        socket_alert_types=alert_types,
    )
    _cache.set(key, result)
    return result
