from __future__ import annotations

import asyncio
import io
import tarfile
from datetime import datetime, timezone

import httpx
from temporalio.exceptions import ApplicationError

from activities.ecosystems import is_major, parse_upload_time, validate_archive_url
from activities.models import MaintainerSignals, PyPISignals, ReleaseAgeSignals


class NpmProvider:
    osv_name = "npm"

    # ------------------------------------------------------------------
    # fetch_metadata
    # ------------------------------------------------------------------

    async def fetch_metadata(
        self, package: str, old_version: str, new_version: str
    ) -> PyPISignals:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(f"https://registry.npmjs.org/{package}/{new_version}")
            if resp.status_code == 404:
                raise ApplicationError(
                    f"{package}@{new_version} not found on npm registry",
                    type="PackageNotFound",
                    non_retryable=True,
                )
            resp.raise_for_status()
            data = resp.json()

            summary = (data.get("description") or "")[:500] or None
            weekly_downloads = await _fetch_weekly_downloads(client, package)

        return PyPISignals(
            weekly_downloads=weekly_downloads,
            publish_account_age_days=None,
            is_major_bump=is_major(old_version, new_version),
            package_description=summary,
        )

    # ------------------------------------------------------------------
    # fetch_release_age
    # ------------------------------------------------------------------

    async def fetch_release_age(self, package: str, new_version: str) -> ReleaseAgeSignals:
        async with httpx.AsyncClient(timeout=15.0) as client:
            # Full package document contains the `time` map: {version: ISO timestamp}
            resp = await client.get(f"https://registry.npmjs.org/{package}")
            if resp.status_code == 404:
                raise ApplicationError(
                    f"{package}@{new_version} not found on npm registry",
                    type="PackageNotFound",
                    non_retryable=True,
                )
            resp.raise_for_status()
            data = resp.json()

        raw = (data.get("time") or {}).get(new_version, "")
        if not raw:
            return ReleaseAgeSignals(release_age_hours=None)

        upload_time = parse_upload_time(raw)
        hours = (datetime.now(timezone.utc) - upload_time).total_seconds() / 3600
        return ReleaseAgeSignals(release_age_hours=max(0.0, hours))

    # ------------------------------------------------------------------
    # fetch_maintainer
    # ------------------------------------------------------------------

    async def fetch_maintainer(
        self, package: str, old_version: str, new_version: str
    ) -> MaintainerSignals:
        async with httpx.AsyncClient(timeout=15.0) as client:
            old_data, new_data = await asyncio.gather(
                _fetch_version(client, package, old_version),
                _fetch_version(client, package, new_version),
            )

        if old_data is None or new_data is None:
            return MaintainerSignals(maintainer_changed=False)

        old_set = _maintainer_set(old_data)
        new_set = _maintainer_set(new_data)
        return MaintainerSignals(maintainer_changed=bool(new_set - old_set))

    # ------------------------------------------------------------------
    # get_archive_url
    # ------------------------------------------------------------------

    async def get_archive_url(
        self, client: httpx.AsyncClient, package: str, version: str
    ) -> tuple[str, str, str] | None:
        resp = await client.get(f"https://registry.npmjs.org/{package}/{version}")
        if resp.status_code == 404:
            raise ApplicationError(
                f"{package}@{version} not found on npm registry",
                type="PackageNotFound",
                non_retryable=True,
            )
        resp.raise_for_status()
        dist = resp.json().get("dist") or {}
        tarball_url = dist.get("tarball", "")
        if not tarball_url:
            return None
        validate_archive_url(tarball_url)
        return tarball_url, tarball_url.split("/")[-1], dist.get("integrity", "")

    # ------------------------------------------------------------------
    # extract_archive
    # ------------------------------------------------------------------

    def extract_archive(self, archive_bytes: bytes, filename: str, dest: str) -> None:
        buf = io.BytesIO(archive_bytes)
        with tarfile.open(fileobj=buf) as tf:
            tf.extractall(dest, filter="data")


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

async def _fetch_weekly_downloads(client: httpx.AsyncClient, package: str) -> int | None:
    try:
        resp = await client.get(f"https://api.npmjs.org/downloads/point/last-week/{package}")
        if resp.status_code == 200:
            return resp.json().get("downloads")
    except Exception:
        pass
    return None


async def _fetch_version(
    client: httpx.AsyncClient, package: str, version: str
) -> dict | None:
    try:
        resp = await client.get(f"https://registry.npmjs.org/{package}/{version}")
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None


def _maintainer_set(data: dict) -> set[str]:
    result = set()
    for m in data.get("maintainers") or []:
        name = (m.get("name") or "").strip().lower()
        if name:
            result.add(name)
    return result
