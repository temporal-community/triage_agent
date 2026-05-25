"""Ecosystem provider for Composer / Packagist (PHP packages).

Package names use vendor/package format: e.g. "laravel/framework", "symfony/console"
"""

from __future__ import annotations

import asyncio
import io
import os
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import httpx
from temporalio.exceptions import ApplicationError

from ecosystems import (
    EcosystemProviderBase,
    build_release_checks,
    fetch_vcs_release,
    fetch_vcs_tag_signature,
    is_major,
    parse_vcs_repo,
    parse_upload_time,
    safe_zip_extractall,
    validate_archive_url,
)
from models import (
    AttestationChecks,
    MaintainerChecks,
    MetadataChecks,
    ReleaseAgeChecks,
    ReleaseChecks,
)
from helpers.http import get_client

_PACKAGIST = "https://packagist.org"
_CODELOAD = "https://codeload.github.com"


class ComposerProvider(EcosystemProviderBase):
    ecosystem_name = "composer"
    osv_name = "Packagist"
    dependabot_slug = "composer"
    name_re = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}/[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")

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
    ) -> MetadataChecks:
        vendor, name = self._parse(package)
        client = get_client()
        resp = await client.get(f"{_PACKAGIST}/packages/{vendor}/{name}.json", timeout=15.0)

        if resp.status_code == 404:
            raise ApplicationError(
                f"{package} not found on Packagist",
                type="PackageNotFound",
                non_retryable=True,
            )
        if resp.status_code != 200:
            return MetadataChecks(is_major_bump=is_major(old_version, new_version))

        pkg = resp.json().get("package", {})
        description = (pkg.get("description") or "").strip()[:500] or None
        # Packagist reports monthly downloads; divide by ~4 for a weekly approximation.
        monthly = pkg.get("downloads", {}).get("monthly")
        weekly = int(monthly / 4) if monthly else None

        return MetadataChecks(
            weekly_downloads=weekly,
            is_major_bump=is_major(old_version, new_version),
            package_description=description,
        )

    # ------------------------------------------------------------------
    # fetch_release_age
    # ------------------------------------------------------------------

    async def fetch_release_age(self, package: str, new_version: str) -> ReleaseAgeChecks:
        vendor, name = self._parse(package)
        client = get_client()
        resp = await client.get(f"{_PACKAGIST}/packages/{vendor}/{name}.json", timeout=15.0)
        if resp.status_code != 200:
            return ReleaseAgeChecks()

        versions = resp.json().get("package", {}).get("versions", {})
        version_data = self._find_version(versions, new_version)
        if not version_data:
            return ReleaseAgeChecks()

        raw_time = version_data.get("time", "")
        if not raw_time:
            return ReleaseAgeChecks()
        try:
            upload_time = parse_upload_time(raw_time)
            hours = (datetime.now(timezone.utc) - upload_time).total_seconds() / 3600
            return ReleaseAgeChecks(release_age_hours=max(0.0, hours))
        except Exception:  # noqa: BLE001
            return ReleaseAgeChecks()

    # ------------------------------------------------------------------
    # fetch_maintainer
    # ------------------------------------------------------------------

    async def fetch_maintainer(
        self, package: str, old_version: str, new_version: str
    ) -> MaintainerChecks:
        vendor, name = self._parse(package)
        client = get_client()
        resp = await client.get(f"{_PACKAGIST}/packages/{vendor}/{name}.json", timeout=15.0)
        if resp.status_code != 200:
            return MaintainerChecks()

        versions = resp.json().get("package", {}).get("versions", {})
        old_data = self._find_version(versions, old_version)
        new_data = self._find_version(versions, new_version)
        if not old_data or not new_data:
            return MaintainerChecks()

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
            return MaintainerChecks()
        return MaintainerChecks(maintainer_changed=bool(new_authors - old_authors))

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
        vcs = parse_vcs_repo(source_url)
        if not vcs:
            return None

        platform, owner_repo = vcs
        owner, repo = owner_repo.split("/", 1)
        filename = f"{name}-{version}.zip"

        for tag in (f"v{version}", version):
            if platform == "github":
                # Direct codeload.github.com URL — no redirect needed.
                url = f"{_CODELOAD}/{owner}/{repo}/zip/refs/tags/{tag}"
            else:
                # GitLab (gitlab.com or self-hosted via GITLAB_BASE_URL)
                base = os.environ.get("GITLAB_BASE_URL", "https://gitlab.com").rstrip("/")
                url = f"{base}/{owner}/{repo}/-/archive/{tag}/{repo}-{tag}.zip"
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
    ) -> AttestationChecks:
        # Packagist/Composer does not have SLSA/Sigstore attestation support.
        return AttestationChecks(has_attestation=False)

    # ------------------------------------------------------------------
    # fetch_release
    # ------------------------------------------------------------------

    async def fetch_release(self, package: str, old_version: str, version: str) -> ReleaseChecks:
        import os

        token = os.environ.get("GITHUB_TOKEN")
        vendor, name = self._parse(package)

        client = get_client()
        resp = await client.get(f"{_PACKAGIST}/packages/{vendor}/{name}.json", timeout=15.0)
        if resp.status_code != 200:
            return ReleaseChecks()

        versions = resp.json().get("package", {}).get("versions", {})
        version_data = self._find_version(versions, version)
        if not version_data:
            return ReleaseChecks()

        registry_time: datetime | None = None
        raw_time = version_data.get("time", "")
        if raw_time:
            try:
                registry_time = parse_upload_time(raw_time)
            except Exception:  # noqa: BLE001
                pass

        source_url = version_data.get("source", {}).get("url", "")
        vcs = parse_vcs_repo(source_url)
        if not vcs:
            return ReleaseChecks()
        platform, owner_repo = vcs

        owner, repo = owner_repo.split("/", 1)
        release, new_sig, old_sig = await asyncio.gather(
            fetch_vcs_release(platform, owner, repo, version, token),
            fetch_vcs_tag_signature(platform, owner, repo, version, token),
            fetch_vcs_tag_signature(platform, owner, repo, old_version, token),
        )
        if release:
            return build_release_checks(release, registry_time, new_sig, old_sig).model_copy(
                update={"metadata_repo": owner_repo}
            )
        return ReleaseChecks(metadata_repo=owner_repo)
