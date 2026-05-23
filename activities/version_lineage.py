"""
Activity: detect whether a version bump targets a stale major line.

Fetches all versions from the registry and checks whether new_version patches an
older major line while a newer stable major is actively maintained. A package
receiving 0.x patches years after 1.x stabilised is a weak supply-chain signal on
its own, but strengthens any concurrent anomalies.
"""
from __future__ import annotations

from datetime import datetime, timezone

import httpx
from temporalio import activity
from temporalio.exceptions import ApplicationError

from activities.ecosystems import detect_stale_version_line, parse_upload_time
from activities.models import VersionLineSignals


@activity.defn(name="activities.version_lineage.check")
async def check(ecosystem: str, package: str, old_version: str, new_version: str) -> VersionLineSignals:
    try:
        if ecosystem == "pip":
            return await _check_pypi(package, new_version)
        if ecosystem == "npm":
            return await _check_npm(package, new_version)
        if ecosystem == "rubygems":
            return await _check_rubygems(package, new_version)
    except ApplicationError:
        raise
    except Exception:  # noqa: BLE001
        pass
    return VersionLineSignals()


async def _check_pypi(package: str, new_version: str) -> VersionLineSignals:
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(f"https://pypi.org/pypi/{package}/json")
    if resp.status_code == 404:
        raise ApplicationError(f"{package} not found on PyPI", type="PackageNotFound", non_retryable=True)
    resp.raise_for_status()
    data = resp.json()

    releases: dict = data.get("releases") or {}
    release_dates: dict[str, datetime] = {}
    for version, files in releases.items():
        for f in files:
            raw = f.get("upload_time_iso_8601") or f.get("upload_time", "")
            if raw:
                try:
                    release_dates[version] = parse_upload_time(raw)
                    break
                except Exception:  # noqa: BLE001
                    pass

    return detect_stale_version_line(list(releases.keys()), new_version, release_dates=release_dates)


async def _check_npm(package: str, new_version: str) -> VersionLineSignals:
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(
            f"https://registry.npmjs.org/{package}",
            headers={"Accept": "application/json"},
        )
    if resp.status_code == 404:
        raise ApplicationError(f"{package} not found on npm", type="PackageNotFound", non_retryable=True)
    resp.raise_for_status()
    data = resp.json()

    time_map: dict[str, str] = data.get("time") or {}
    all_versions = [v for v in time_map if v not in ("created", "modified")]
    release_dates: dict[str, datetime] = {}
    for version, raw in time_map.items():
        if version in ("created", "modified"):
            continue
        try:
            release_dates[version] = parse_upload_time(raw)
        except Exception:  # noqa: BLE001
            pass

    return detect_stale_version_line(all_versions, new_version, release_dates=release_dates)


async def _check_rubygems(package: str, new_version: str) -> VersionLineSignals:
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(f"https://rubygems.org/api/v1/versions/{package}.json")
    if resp.status_code == 404:
        raise ApplicationError(f"{package} not found on RubyGems", type="PackageNotFound", non_retryable=True)
    resp.raise_for_status()
    versions_data: list[dict] = resp.json()

    all_versions = [v.get("number", "") for v in versions_data if v.get("number")]
    release_dates: dict[str, datetime] = {}
    for v in versions_data:
        number = v.get("number", "")
        raw = v.get("created_at", "")
        if number and raw:
            try:
                release_dates[number] = parse_upload_time(raw)
            except Exception:  # noqa: BLE001
                pass

    return detect_stale_version_line(all_versions, new_version, release_dates=release_dates)
