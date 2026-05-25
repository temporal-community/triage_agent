"""
Activity: detect whether a version bump targets a stale major line.

Fetches all versions from the registry and checks whether new_version patches an
older major line while a newer stable major is actively maintained. A package
receiving 0.x patches years after 1.x stabilised is a weak supply-chain signal on
its own, but strengthens any concurrent anomalies.
"""

from __future__ import annotations

from datetime import datetime, timezone

from temporalio import activity
from temporalio.exceptions import ApplicationError

from ecosystems import detect_stale_version_line, parse_upload_time
from models import VersionLineageChecks
from helpers.cache import ActivityCache
from helpers.http import get_client

_cache: ActivityCache = ActivityCache(ttl_seconds=3600)  # new majors can be released; 1h TTL


@activity.defn(name="activities.version_lineage.check")
async def check(
    ecosystem: str, package: str, old_version: str, new_version: str
) -> VersionLineageChecks:
    key = (ecosystem, package, new_version)
    if (hit := _cache.get(key)) is not None:
        activity.logger.debug("version_lineage cache hit: %s %s", package, new_version)
        return hit

    result: VersionLineageChecks
    try:
        if ecosystem == "pip":
            result = await _check_pypi(package, new_version)
        elif ecosystem == "npm":
            result = await _check_npm(package, new_version)
        elif ecosystem == "rubygems":
            result = await _check_rubygems(package, new_version)
        elif ecosystem == "maven":
            result = await _check_maven(package, new_version)
        elif ecosystem == "composer":
            result = await _check_composer(package, new_version)
        elif ecosystem == "nuget":
            result = await _check_nuget(package, new_version)
        elif ecosystem == "cargo":
            result = await _check_cargo(package, new_version)
        else:
            return VersionLineageChecks()
    except ApplicationError:
        raise
    except Exception:  # noqa: BLE001
        return VersionLineageChecks()

    _cache.set(key, result)
    return result


async def _check_pypi(package: str, new_version: str) -> VersionLineageChecks:
    client = get_client()
    resp = await client.get(f"https://pypi.org/pypi/{package}/json", timeout=15.0)
    if resp.status_code == 404:
        raise ApplicationError(
            f"{package} not found on PyPI", type="PackageNotFound", non_retryable=True
        )
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

    return detect_stale_version_line(
        list(releases.keys()), new_version, release_dates=release_dates
    )


async def _check_npm(package: str, new_version: str) -> VersionLineageChecks:
    client = get_client()
    resp = await client.get(
        f"https://registry.npmjs.org/{package}",
        headers={"Accept": "application/json"},
        timeout=15.0,
    )
    if resp.status_code == 404:
        raise ApplicationError(
            f"{package} not found on npm", type="PackageNotFound", non_retryable=True
        )
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


async def _check_composer(package: str, new_version: str) -> VersionLineageChecks:
    """Use the Packagist API to get all versions for a vendor/package."""
    if "/" not in package:
        return VersionLineageChecks()
    vendor, name = package.split("/", 1)
    client = get_client()
    resp = await client.get(f"https://packagist.org/packages/{vendor}/{name}.json", timeout=15.0)
    if resp.status_code == 404:
        raise ApplicationError(
            f"{package} not found on Packagist", type="PackageNotFound", non_retryable=True
        )
    if resp.status_code != 200:
        return VersionLineageChecks()

    versions: dict = resp.json().get("package", {}).get("versions", {})
    if not versions:
        return VersionLineageChecks()

    all_versions: list[str] = []
    release_dates: dict[str, datetime] = {}
    for vkey, vdata in versions.items():
        # Skip Packagist dev-branch aliases (e.g. "dev-main", "dev-develop")
        if vkey.startswith("dev-"):
            continue
        all_versions.append(vkey)
        raw_time = vdata.get("time", "")
        if raw_time:
            try:
                release_dates[vkey] = parse_upload_time(raw_time)
            except Exception:  # noqa: BLE001
                pass

    return detect_stale_version_line(all_versions, new_version, release_dates=release_dates)


async def _check_maven(package: str, new_version: str) -> VersionLineageChecks:
    """Use search.maven.org to get all versions for a groupId:artifactId package."""
    if ":" not in package:
        return VersionLineageChecks()
    group_id, artifact_id = package.split(":", 1)
    client = get_client()
    resp = await client.get(
        "https://search.maven.org/solrsearch/select",
        params={
            "q": f"g:{group_id} AND a:{artifact_id}",
            "core": "gav",
            "rows": "200",
            "wt": "json",
        },
        timeout=15.0,
    )
    if resp.status_code != 200:
        return VersionLineageChecks()

    docs = resp.json().get("response", {}).get("docs", [])
    if not docs:
        return VersionLineageChecks()

    release_dates: dict[str, datetime] = {}
    all_versions: list[str] = []
    for doc in docs:
        version = doc.get("v", "")
        if not version or "SNAPSHOT" in version.upper():
            continue
        all_versions.append(version)
        ts_ms = doc.get("timestamp")
        if ts_ms is not None:
            try:
                release_dates[version] = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
            except Exception:  # noqa: BLE001
                pass

    return detect_stale_version_line(all_versions, new_version, release_dates=release_dates)


async def _check_nuget(package: str, new_version: str) -> VersionLineageChecks:
    """Use the NuGet flat-container version index to detect stale major-line bumps."""
    id_lower = package.lower()
    client = get_client()
    resp = await client.get(
        f"https://api.nuget.org/v3-flatcontainer/{id_lower}/index.json", timeout=15.0
    )
    if resp.status_code == 404:
        raise ApplicationError(
            f"{package} not found on NuGet", type="PackageNotFound", non_retryable=True
        )
    if resp.status_code != 200:
        return VersionLineageChecks()
    versions: list[str] = resp.json().get("versions", [])
    return detect_stale_version_line(versions, new_version)


async def _check_cargo(package: str, new_version: str) -> VersionLineageChecks:
    """Use the crates.io API to detect stale major-line bumps."""
    client = get_client()
    headers = {
        "User-Agent": "dependabot-supply-chain-scout/1.0 (security scanner; https://github.com/temporal-community/dependabot-supply-chain-scout)"
    }
    resp = await client.get(
        f"https://crates.io/api/v1/crates/{package}", headers=headers, timeout=15.0
    )
    if resp.status_code == 404:
        raise ApplicationError(
            f"{package} not found on crates.io", type="PackageNotFound", non_retryable=True
        )
    resp.raise_for_status()
    data = resp.json()

    all_versions: list[str] = []
    release_dates: dict[str, datetime] = {}
    for v in data.get("versions", []):
        num = v.get("num", "")
        if not num or v.get("yanked"):
            continue
        all_versions.append(num)
        raw = v.get("created_at", "")
        if raw:
            try:
                release_dates[num] = parse_upload_time(raw)
            except Exception:  # noqa: BLE001
                pass

    return detect_stale_version_line(all_versions, new_version, release_dates=release_dates)


async def _check_rubygems(package: str, new_version: str) -> VersionLineageChecks:
    client = get_client()
    resp = await client.get(f"https://rubygems.org/api/v1/versions/{package}.json", timeout=15.0)
    if resp.status_code == 404:
        raise ApplicationError(
            f"{package} not found on RubyGems", type="PackageNotFound", non_retryable=True
        )
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
