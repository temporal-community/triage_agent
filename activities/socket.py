import os

import httpx
from temporalio import activity
from temporalio.exceptions import ApplicationError

from activities.models import SocketSignals

_ECOSYSTEM_MAP = {"pip": "pypi", "npm": "npm"}
_INCLUDE_SEVERITIES = {"critical", "high"}


@activity.defn(name="activities.socket.score")
async def score(ecosystem: str, package: str, old_version: str, new_version: str) -> SocketSignals:
    api_key = os.environ.get("SOCKET_API_KEY")
    if not api_key:
        activity.logger.info("No SOCKET_API_KEY — skipping Socket score (treated as yellow indicator)")
        return SocketSignals(socket_score=None, socket_alerts=[])

    ecosystem_slug = _ECOSYSTEM_MAP.get(ecosystem, "pypi")
    purl = f"pkg:{ecosystem_slug}/{package}@{new_version}"

    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(
            "https://api.socket.dev/v0/purl",
            headers={"Authorization": f"Bearer {api_key}"},
            json={"components": [{"purl": purl}]},
            params={"alerts": "true"},
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

    alerts = [
        f"[{a['severity']}] {a.get('type', 'unknown')}: {a.get('message', '').strip()}"
        for a in pkg.get("alerts", [])
        if a.get("severity") in _INCLUDE_SEVERITIES
    ]

    activity.logger.info(
        f"Socket: {package}@{new_version} score={socket_score} alerts={len(alerts)}"
    )
    return SocketSignals(socket_score=socket_score, socket_alerts=alerts)
