from __future__ import annotations

import asyncio
import io
import tarfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import httpx
from temporalio.exceptions import ApplicationError

from activities.ecosystems import (
    is_major,
    parse_upload_time,
    safe_zip_extractall,
    validate_archive_url,
)
from activities.models import AttestationSignals, MaintainerSignals, PyPISignals, ReleaseAgeSignals


class PipProvider:
    osv_name = "PyPI"

    # ------------------------------------------------------------------
    # fetch_metadata
    # ------------------------------------------------------------------

    async def fetch_metadata(
        self, package: str, old_version: str, new_version: str
    ) -> PyPISignals:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(f"https://pypi.org/pypi/{package}/{new_version}/json")
            if resp.status_code == 404:
                raise ApplicationError(
                    f"{package}=={new_version} not found on PyPI",
                    type="PackageNotFound",
                    non_retryable=True,
                )
            resp.raise_for_status()
            data = resp.json()

            summary = data.get("info", {}).get("summary") or None
            if summary:
                summary = summary[:500]

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
            resp = await client.get(f"https://pypi.org/pypi/{package}/{new_version}/json")
            if resp.status_code == 404:
                raise ApplicationError(
                    f"{package}=={new_version} not found on PyPI",
                    type="PackageNotFound",
                    non_retryable=True,
                )
            resp.raise_for_status()
            data = resp.json()

        urls = data.get("urls", [])
        if not urls:
            return ReleaseAgeSignals(release_age_hours=None)

        raw = urls[0].get("upload_time_iso_8601") or urls[0].get("upload_time", "")
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
            old_info, new_info = await asyncio.gather(
                _fetch_version_info(client, package, old_version),
                _fetch_version_info(client, package, new_version),
            )

        if old_info is None or new_info is None:
            return MaintainerSignals(maintainer_changed=False)

        old_set = _maintainer_set(old_info)
        new_set = _maintainer_set(new_info)
        return MaintainerSignals(maintainer_changed=bool(new_set - old_set))

    # ------------------------------------------------------------------
    # get_archive_url
    # ------------------------------------------------------------------

    async def get_archive_url(
        self, client: httpx.AsyncClient, package: str, version: str
    ) -> tuple[str, str, str] | None:
        resp = await client.get(f"https://pypi.org/pypi/{package}/{version}/json")
        if resp.status_code == 404:
            raise ApplicationError(
                f"{package}=={version} not found on PyPI",
                type="PackageNotFound",
                non_retryable=True,
            )
        resp.raise_for_status()
        urls: list[dict] = resp.json().get("urls", [])

        for pkg_type in ("sdist", "bdist_wheel"):
            for entry in urls:
                if entry.get("packagetype") == pkg_type:
                    url = entry["url"]
                    validate_archive_url(url)
                    return url, entry["filename"], entry.get("digests", {}).get("sha256", "")

        return None

    # ------------------------------------------------------------------
    # extract_archive
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # fetch_attestations
    # ------------------------------------------------------------------

    async def fetch_attestations(
        self, package: str, old_version: str, new_version: str
    ) -> AttestationSignals:
        async with httpx.AsyncClient(timeout=15.0) as client:
            new_pub, old_pub = await asyncio.gather(
                _fetch_pypi_publisher(client, package, new_version),
                _fetch_pypi_publisher(client, package, old_version),
            )

        if new_pub is None:
            return AttestationSignals(has_attestation=False)

        publisher_changed = old_pub is not None and old_pub != new_pub
        return AttestationSignals(
            has_attestation=True,
            publisher_kind=new_pub.get("kind"),
            publisher_repo=new_pub.get("repo"),
            publisher_changed=publisher_changed,
            old_publisher_repo=old_pub.get("repo") if publisher_changed else None,
        )

    def extract_archive(self, archive_bytes: bytes, filename: str, dest: str) -> None:
        buf = io.BytesIO(archive_bytes)
        dest_path = Path(dest).resolve()
        lower = filename.lower()
        if lower.endswith((".tar.gz", ".tar.bz2", ".tgz")):
            with tarfile.open(fileobj=buf) as tf:
                tf.extractall(dest, filter="data")
        elif lower.endswith((".whl", ".zip")):
            with zipfile.ZipFile(buf) as zf:
                safe_zip_extractall(zf, dest_path)
        else:
            raise ValueError(f"Unsupported PyPI archive format: {filename}")


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

async def _fetch_weekly_downloads(client: httpx.AsyncClient, package: str) -> int | None:
    try:
        resp = await client.get(
            f"https://pypistats.org/api/packages/{package.lower()}/recent",
            headers={"Accept": "application/json"},
        )
        if resp.status_code == 200:
            return resp.json()["data"]["last_week"]
    except Exception:
        pass
    return None


async def _fetch_version_info(
    client: httpx.AsyncClient, package: str, version: str
) -> dict | None:
    try:
        resp = await client.get(f"https://pypi.org/pypi/{package}/{version}/json")
        if resp.status_code == 200:
            return resp.json().get("info", {})
    except Exception:
        pass
    return None


def _maintainer_set(info: dict) -> set[str]:
    result = set()
    for field in ("author", "maintainer", "author_email", "maintainer_email"):
        val = (info.get(field) or "").strip().lower()
        if val and val not in ("none", "unknown", ""):
            result.add(val)
    return result


async def _fetch_pypi_publisher(
    client: httpx.AsyncClient, package: str, version: str
) -> dict | None:
    """Return {"kind": ..., "repo": ...} from the PEP 740 provenance endpoint, or None.

    PyPI generates attestations automatically for packages published via a
    Trusted Publisher (GitHub Actions, GitLab CI, etc.).  A 404 means the
    version was uploaded with a plain API token and has no attestation.
    """
    try:
        resp = await client.get(f"https://pypi.org/pypi/{package}/{version}/json")
        if resp.status_code != 200:
            return None
        urls = resp.json().get("urls", [])
        # Prefer sdist; any file works since provenance is per-file
        filename = next(
            (u["filename"] for u in urls if u.get("packagetype") == "sdist"),
            urls[0]["filename"] if urls else None,
        )
        if not filename:
            return None

        prov = await client.get(
            f"https://pypi.org/integrity/{package}/{version}/{filename}/provenance"
        )
        if prov.status_code != 200:
            return None

        bundles = prov.json().get("attestation_bundles", [])
        if not bundles:
            return None
        pub = bundles[0].get("publisher", {})
        claims = pub.get("claims", {})
        return {"kind": pub.get("kind"), "repo": claims.get("repository")}
    except Exception:
        return None
