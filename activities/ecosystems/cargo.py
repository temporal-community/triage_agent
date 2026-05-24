from __future__ import annotations

import asyncio
import io
import re
import tarfile
from datetime import datetime, timezone

import httpx
from temporalio.exceptions import ApplicationError

from activities.ecosystems import (
    build_release_signals,
    fetch_vcs_release,
    fetch_vcs_tag_signature,
    is_major,
    parse_vcs_repo,
    parse_upload_time,
    validate_archive_url,
)
from activities.models import (
    AttestationSignals,
    MaintainerSignals,
    PyPISignals,
    ReleaseAgeSignals,
    ReleaseSignals,
)

# crates.io requires a descriptive User-Agent per their crawling policy.
_HEADERS = {
    "User-Agent": "dependabot-supply-chain-scout/1.0 (security scanner; https://github.com/temporal-community/dependabot-supply-chain-scout)"
}
_API_BASE = "https://crates.io/api/v1"


class CargoProvider:
    ecosystem_name = "cargo"
    osv_name = "crates.io"
    dependabot_slug = "cargo"
    name_re = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")

    # ------------------------------------------------------------------
    # fetch_metadata
    # ------------------------------------------------------------------

    async def fetch_metadata(self, package: str, old_version: str, new_version: str) -> PyPISignals:
        async with httpx.AsyncClient(timeout=15.0, headers=_HEADERS) as client:
            resp = await client.get(f"{_API_BASE}/crates/{package}")
            if resp.status_code == 404:
                raise ApplicationError(
                    f"{package} not found on crates.io",
                    type="PackageNotFound",
                    non_retryable=True,
                )
            resp.raise_for_status()
            data = resp.json()

        crate = data.get("crate", {})
        description = (crate.get("description") or "")[:500] or None
        # recent_downloads is a 90-day window — the closest crates.io offers to weekly
        recent_downloads = crate.get("recent_downloads")
        return PyPISignals(
            weekly_downloads=recent_downloads,
            is_major_bump=is_major(old_version, new_version),
            package_description=description,
        )

    # ------------------------------------------------------------------
    # fetch_release_age
    # ------------------------------------------------------------------

    async def fetch_release_age(self, package: str, new_version: str) -> ReleaseAgeSignals:
        async with httpx.AsyncClient(timeout=15.0, headers=_HEADERS) as client:
            resp = await client.get(f"{_API_BASE}/crates/{package}")
            if resp.status_code == 404:
                raise ApplicationError(
                    f"{package} not found on crates.io",
                    type="PackageNotFound",
                    non_retryable=True,
                )
            resp.raise_for_status()
            data = resp.json()

        for v in data.get("versions", []):
            if v.get("num") == new_version:
                raw = v.get("created_at", "")
                if not raw:
                    return ReleaseAgeSignals(release_age_hours=None)
                upload_time = parse_upload_time(raw)
                hours = (datetime.now(timezone.utc) - upload_time).total_seconds() / 3600
                return ReleaseAgeSignals(release_age_hours=max(0.0, hours))

        return ReleaseAgeSignals(release_age_hours=None)

    # ------------------------------------------------------------------
    # fetch_maintainer
    # ------------------------------------------------------------------

    async def fetch_maintainer(
        self, package: str, old_version: str, new_version: str
    ) -> MaintainerSignals:
        async with httpx.AsyncClient(timeout=15.0, headers=_HEADERS) as client:
            try:
                resp = await client.get(f"{_API_BASE}/crates/{package}")
                if resp.status_code != 200:
                    return MaintainerSignals(maintainer_changed=False)
                versions = resp.json().get("versions", [])
            except Exception:
                return MaintainerSignals(maintainer_changed=False)

        # crates.io records the GitHub login of whoever published each version
        old_publisher: str | None = None
        new_publisher: str | None = None
        for v in versions:
            num = v.get("num", "")
            login = (v.get("published_by") or {}).get("login")
            if num == old_version:
                old_publisher = login
            elif num == new_version:
                new_publisher = login

        if not old_publisher or not new_publisher:
            return MaintainerSignals(maintainer_changed=False)

        return MaintainerSignals(maintainer_changed=old_publisher != new_publisher)

    # ------------------------------------------------------------------
    # get_archive_url
    # ------------------------------------------------------------------

    async def get_archive_url(
        self, client: httpx.AsyncClient, package: str, version: str
    ) -> tuple[str, str, str] | None:
        resp = await client.get(f"{_API_BASE}/crates/{package}", headers=_HEADERS)
        if resp.status_code == 404:
            raise ApplicationError(
                f"{package} not found on crates.io",
                type="PackageNotFound",
                non_retryable=True,
            )
        resp.raise_for_status()

        for v in resp.json().get("versions", []):
            if v.get("num") == version:
                checksum = v.get("checksum", "")
                filename = f"{package}-{version}.crate"
                url = f"https://static.crates.io/crates/{package}/{filename}"
                validate_archive_url(url)
                return url, filename, checksum

        return None

    # ------------------------------------------------------------------
    # extract_archive
    # ------------------------------------------------------------------

    def extract_archive(self, archive_bytes: bytes, filename: str, dest: str) -> None:
        """Extract a .crate file (gzipped tarball) to dest."""
        buf = io.BytesIO(archive_bytes)
        with tarfile.open(fileobj=buf, mode="r:gz") as tf:
            tf.extractall(dest, filter="data")

    # ------------------------------------------------------------------
    # fetch_attestations
    # ------------------------------------------------------------------

    async def fetch_attestations(
        self, package: str, old_version: str, new_version: str
    ) -> AttestationSignals:
        # crates.io does not yet support SLSA provenance or Sigstore attestations.
        return AttestationSignals(has_attestation=False)

    # ------------------------------------------------------------------
    # fetch_release
    # ------------------------------------------------------------------

    async def fetch_release(self, package: str, old_version: str, version: str) -> ReleaseSignals:
        import os

        token = os.environ.get("GITHUB_TOKEN")
        async with httpx.AsyncClient(timeout=15.0, headers=_HEADERS) as client:
            resp = await client.get(f"{_API_BASE}/crates/{package}")

        if resp.status_code != 200:
            return ReleaseSignals()
        data = resp.json()
        crate = data.get("crate", {})

        source_url = crate.get("repository") or ""
        vcs = parse_vcs_repo(source_url)
        if not vcs:
            return ReleaseSignals()
        platform, owner_repo = vcs

        registry_time = None
        for v in data.get("versions", []):
            if v.get("num") == version:
                raw = v.get("created_at", "")
                if raw:
                    try:
                        registry_time = parse_upload_time(raw)
                    except Exception:  # noqa: BLE001
                        pass
                break

        owner, repo = owner_repo.split("/", 1)
        release, new_sig, old_sig = await asyncio.gather(
            fetch_vcs_release(platform, owner, repo, version, token),
            fetch_vcs_tag_signature(platform, owner, repo, version, token),
            fetch_vcs_tag_signature(platform, owner, repo, old_version, token),
        )
        if release:
            return build_release_signals(release, registry_time, new_sig, old_sig).model_copy(
                update={"metadata_repo": owner_repo}
            )
        return ReleaseSignals(metadata_repo=owner_repo)
