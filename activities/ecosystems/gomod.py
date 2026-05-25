"""Ecosystem provider for Go Modules (proxy.golang.org).

Module paths use reverse-DNS format: e.g. "github.com/gorilla/mux", "golang.org/x/net"
Major versions beyond v1 are encoded in the path: "github.com/foo/bar/v2"
"""

from __future__ import annotations

import asyncio
import io
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import httpx
from temporalio.exceptions import ApplicationError

from activities.ecosystems import (
    build_release_signals,
    fetch_vcs_release,
    fetch_vcs_tag_signature,
    is_major,
    parse_vcs_repo,
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
from helpers.http import get_client

_PROXY = "https://proxy.golang.org"


def _escape(module: str) -> str:
    """Encode uppercase letters per GOPROXY protocol: 'A' → '!a'."""
    return re.sub(r"[A-Z]", lambda m: "!" + m.group().lower(), module)


class GoModulesProvider:
    ecosystem_name = "go"
    osv_name = "Go"
    dependabot_slug = "go_modules"
    name_re = re.compile(r"^(?!.*\.\.)[a-zA-Z0-9][a-zA-Z0-9._/\-~]{0,499}$")

    # ------------------------------------------------------------------
    # fetch_metadata
    # ------------------------------------------------------------------

    async def fetch_metadata(self, package: str, old_version: str, new_version: str) -> PyPISignals:
        # Go proxy has no download counts or description API; only version info.
        client = get_client()
        resp = await client.get(f"{_PROXY}/{_escape(package)}/@v/{new_version}.info", timeout=15.0)
        if resp.status_code in (404, 410):
            raise ApplicationError(
                f"{package}@{new_version} not found on Go proxy",
                type="PackageNotFound",
                non_retryable=True,
            )
        resp.raise_for_status()

        return PyPISignals(
            weekly_downloads=None,  # not available from Go proxy
            is_major_bump=is_major(old_version, new_version),
            package_description=None,
        )

    # ------------------------------------------------------------------
    # fetch_release_age
    # ------------------------------------------------------------------

    async def fetch_release_age(self, package: str, new_version: str) -> ReleaseAgeSignals:
        client = get_client()
        resp = await client.get(f"{_PROXY}/{_escape(package)}/@v/{new_version}.info", timeout=15.0)
        if resp.status_code in (404, 410):
            raise ApplicationError(
                f"{package}@{new_version} not found on Go proxy",
                type="PackageNotFound",
                non_retryable=True,
            )
        resp.raise_for_status()
        data = resp.json()

        raw = data.get("Time", "")
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
        # Go proxy has no per-version publisher concept; the VCS repo is
        # the authority and ownership changes would change the module path.
        return MaintainerSignals(maintainer_changed=False)

    # ------------------------------------------------------------------
    # get_archive_url
    # ------------------------------------------------------------------

    async def get_archive_url(
        self, client: httpx.AsyncClient, package: str, version: str
    ) -> tuple[str, str, str] | None:
        url = f"{_PROXY}/{_escape(package)}/@v/{version}.zip"
        validate_archive_url(url)
        filename = f"{package.replace('/', '_')}@{version}.zip"
        return url, filename, ""  # checksum available via sum.golang.org but not needed here

    # ------------------------------------------------------------------
    # extract_archive
    # ------------------------------------------------------------------

    def extract_archive(self, archive_bytes: bytes, filename: str, dest: str) -> None:
        """Extract a Go module zip. All entries are prefixed {module}@{version}/."""
        buf = io.BytesIO(archive_bytes)
        dest_path = Path(dest)
        with zipfile.ZipFile(buf) as zf:
            safe_zip_extractall(zf, dest_path)

    # ------------------------------------------------------------------
    # fetch_attestations
    # ------------------------------------------------------------------

    async def fetch_attestations(
        self, package: str, old_version: str, new_version: str
    ) -> AttestationSignals:
        # Go modules use the sum database (sum.golang.org) for transparency,
        # but Sigstore-style SLSA attestations are not yet standard.
        return AttestationSignals(has_attestation=False)

    # ------------------------------------------------------------------
    # fetch_release
    # ------------------------------------------------------------------

    async def fetch_release(self, package: str, old_version: str, version: str) -> ReleaseSignals:
        import os

        token = os.environ.get("GITHUB_TOKEN")

        # The .info Origin.URL field gives the canonical VCS repo URL.
        client = get_client()
        new_info, old_info = await asyncio.gather(
            client.get(f"{_PROXY}/{_escape(package)}/@v/{version}.info", timeout=15.0),
            client.get(f"{_PROXY}/{_escape(package)}/@v/{old_version}.info", timeout=15.0),
        )

        if new_info.status_code != 200:
            return ReleaseSignals()

        data = new_info.json()
        source_url = (data.get("Origin") or {}).get("URL") or ""
        vcs = parse_vcs_repo(source_url)
        if not vcs:
            return ReleaseSignals()
        platform, owner_repo = vcs

        registry_time = None
        raw = data.get("Time", "")
        if raw:
            try:
                registry_time = parse_upload_time(raw)
            except Exception:  # noqa: BLE001
                pass

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
