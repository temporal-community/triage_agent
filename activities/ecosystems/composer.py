"""Ecosystem provider for Composer / Packagist (PHP packages).

Package names use vendor/package format: e.g. "laravel/framework", "symfony/console"
"""
from __future__ import annotations

import asyncio
import io
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import httpx
from temporalio.exceptions import ApplicationError

from activities.ecosystems import (
    build_release_signals,
    fetch_github_release,
    fetch_tag_signature,
    is_major,
    parse_github_repo,
    parse_upload_time,
    safe_zip_extractall,
    validate_archive_url,
)
from activities.models import (
    AttestationSignals,
    MaintainerSignals,
    PyPISignals,
    ReleaseAgeSignals,
    ReleaseSignals,
)

_PACKAGIST = "https://packagist.org"
_CODELOAD  = "https://codeload.github.com"


class ComposerProvider:
    osv_name = "Packagist"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse(self, package: str) -> tuple[str, str]:
        """Split 'vendor/package' → (vendor, name)."""
        if "/" not in package:
            raise ApplicationError(
                f"Invalid Composer package format: {package!r} — expected vendor/package",
                non_retryable=True,
            )
        vendor, name = package.split("/", 1)
        return vendor, name

    def _find_version(self, versions: dict, version: str) -> dict | None:
        """Look up a version by exact key or with 'v' prefix (Packagist stores both forms)."""
        return versions.get(version) or versions.get(f"v{version}")

    # ------------------------------------------------------------------
    # fetch_metadata
    # ------------------------------------------------------------------

    async def fetch_metadata(
        self, package: str, old_version: str, new_version: str
    ) -> PyPISignals:
        vendor, name = self._parse(package)
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(f"{_PACKAGIST}/packages/{vendor}/{name}.json")

        if resp.status_code == 404:
            raise ApplicationError(
                f"{package} not found on Packagist",
                type="PackageNotFound",
                non_retryable=True,
            )
        if resp.status_code != 200:
            return PyPISignals(is_major_bump=is_major(old_version, new_version))

        pkg = resp.json().get("package", {})
        description = (pkg.get("description") or "").strip()[:500] or None
        # Packagist reports monthly downloads; divide by ~4 for a weekly approximation.
        monthly = pkg.get("downloads", {}).get("monthly")
        weekly = int(monthly / 4) if monthly else None

        return PyPISignals(
            weekly_downloads=weekly,
            is_major_bump=is_major(old_version, new_version),
            package_description=description,
        )

    # ------------------------------------------------------------------
    # fetch_release_age
    # ------------------------------------------------------------------

    async def fetch_release_age(self, package: str, new_version: str) -> ReleaseAgeSignals:
        vendor, name = self._parse(package)
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(f"{_PACKAGIST}/packages/{vendor}/{name}.json")
        if resp.status_code != 200:
            return ReleaseAgeSignals()

        versions = resp.json().get("package", {}).get("versions", {})
        version_data = self._find_version(versions, new_version)
        if not version_data:
            return ReleaseAgeSignals()

        raw_time = version_data.get("time", "")
        if not raw_time:
            return ReleaseAgeSignals()
        try:
            upload_time = parse_upload_time(raw_time)
            hours = (datetime.now(timezone.utc) - upload_time).total_seconds() / 3600
            return ReleaseAgeSignals(release_age_hours=max(0.0, hours))
        except Exception:  # noqa: BLE001
            return ReleaseAgeSignals()

    # ------------------------------------------------------------------
    # fetch_maintainer
    # ------------------------------------------------------------------

    async def fetch_maintainer(
        self, package: str, old_version: str, new_version: str
    ) -> MaintainerSignals:
        vendor, name = self._parse(package)
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(f"{_PACKAGIST}/packages/{vendor}/{name}.json")
        if resp.status_code != 200:
            return MaintainerSignals()

        versions = resp.json().get("package", {}).get("versions", {})
        old_data = self._find_version(versions, old_version)
        new_data = self._find_version(versions, new_version)
        if not old_data or not new_data:
            return MaintainerSignals()

        def _authors(vdata: dict) -> set[str]:
            result: set[str] = set()
            for author in vdata.get("authors", []):
                n = (author.get("name") or "").lower().strip()
                e = (author.get("email") or "").lower().strip()
                if n:
                    result.add(n)
                elif e:
                    result.add(e)
            return result

        old_authors = _authors(old_data)
        new_authors = _authors(new_data)
        if not old_authors or not new_authors:
            return MaintainerSignals()
        return MaintainerSignals(maintainer_changed=bool(new_authors - old_authors))

    # ------------------------------------------------------------------
    # get_archive_url
    # ------------------------------------------------------------------

    async def get_archive_url(
        self, client: httpx.AsyncClient, package: str, version: str
    ) -> tuple[str, str, str] | None:
        vendor, name = self._parse(package)
        try:
            resp = await client.get(f"{_PACKAGIST}/packages/{vendor}/{name}.json")
        except Exception:  # noqa: BLE001
            return None
        if resp.status_code != 200:
            return None

        versions = resp.json().get("package", {}).get("versions", {})
        version_data = self._find_version(versions, version)
        if not version_data:
            return None

        source_url = version_data.get("source", {}).get("url", "")
        owner_repo = parse_github_repo(source_url)
        if not owner_repo:
            return None

        owner, repo = owner_repo.split("/", 1)
        filename = f"{name}-{version}.zip"

        # Construct direct codeload.github.com archive URL — no redirect needed.
        # Try v-prefixed tag first (most PHP packages tag as vX.Y.Z).
        for tag in (f"v{version}", version):
            url = f"{_CODELOAD}/{owner}/{repo}/zip/refs/tags/{tag}"
            validate_archive_url(url)
            try:
                head = await client.head(url, follow_redirects=True)
                if head.status_code == 200:
                    return url, filename, ""
            except Exception:  # noqa: BLE001
                continue

        return None

    # ------------------------------------------------------------------
    # extract_archive
    # ------------------------------------------------------------------

    def extract_archive(self, archive_bytes: bytes, filename: str, dest: str) -> None:
        """Composer archives from GitHub are standard ZIPs."""
        buf = io.BytesIO(archive_bytes)
        dest_path = Path(dest).resolve()
        with zipfile.ZipFile(buf) as zf:
            safe_zip_extractall(zf, dest_path)

    # ------------------------------------------------------------------
    # fetch_attestations
    # ------------------------------------------------------------------

    async def fetch_attestations(
        self, package: str, old_version: str, new_version: str
    ) -> AttestationSignals:
        # Packagist/Composer does not have SLSA/Sigstore attestation support.
        return AttestationSignals(has_attestation=False)

    # ------------------------------------------------------------------
    # fetch_release
    # ------------------------------------------------------------------

    async def fetch_release(
        self, package: str, old_version: str, version: str
    ) -> ReleaseSignals:
        import os
        token = os.environ.get("GITHUB_TOKEN")
        vendor, name = self._parse(package)

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(f"{_PACKAGIST}/packages/{vendor}/{name}.json")
        if resp.status_code != 200:
            return ReleaseSignals()

        versions = resp.json().get("package", {}).get("versions", {})
        version_data = self._find_version(versions, version)
        if not version_data:
            return ReleaseSignals()

        registry_time: datetime | None = None
        raw_time = version_data.get("time", "")
        if raw_time:
            try:
                registry_time = parse_upload_time(raw_time)
            except Exception:  # noqa: BLE001
                pass

        source_url = version_data.get("source", {}).get("url", "")
        owner_repo = parse_github_repo(source_url)
        if not owner_repo:
            return ReleaseSignals()

        owner, repo = owner_repo.split("/", 1)
        release, new_sig, old_sig = await asyncio.gather(
            fetch_github_release(owner, repo, version, token),
            fetch_tag_signature(owner, repo, version, token),
            fetch_tag_signature(owner, repo, old_version, token),
        )
        if release:
            return build_release_signals(release, registry_time, new_sig, old_sig).model_copy(
                update={"metadata_repo": owner_repo}
            )
        return ReleaseSignals(metadata_repo=owner_repo)
