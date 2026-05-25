"""Base class for bridge providers that delegate signal fetching to a remote HTTP service.

This lets non-Python teams (PHP, Go, Rust, …) implement ecosystem-specific logic in their
own stack. The core project defines the HTTP protocol; bridge packages are ~10 lines:

    # pyproject.toml
    [project.entry-points."dependency_scout.ecosystems"]
    drupal = "dependency_scout_drupal:DrupalProvider"

    # dependency_scout_drupal/__init__.py
    import re
    from activities.ecosystems.remote import RemoteEcosystemProvider

    class DrupalProvider(RemoteEcosystemProvider):
        ecosystem_name  = "drupal"
        osv_name        = "Packagist"
        dependabot_slug = "drupal"
        name_re         = re.compile(r"^[a-z0-9_-]+/[a-z0-9_-]+$")
        remote_base_url = "https://drupal-bridge.example.com/triage/v1"

The remote service must expose POST endpoints at {remote_base_url}/{method_name}.
See the docstrings on each method below for the expected request/response shapes.
"""

from __future__ import annotations

import io
import re
import stat
import tarfile
import zipfile
from pathlib import Path
from typing import Any

import httpx
from temporalio.exceptions import ApplicationError

from activities.ecosystems import MAX_EXTRACT_BYTES, validate_archive_url
from activities.models import (
    AttestationSignals,
    MaintainerSignals,
    PyPISignals,
    ReleaseAgeSignals,
    ReleaseSignals,
)
from helpers.http import get_client


class RemoteEcosystemProvider:
    """Delegate all EcosystemProvider calls to a remote HTTP service.

    Subclasses must declare five class attributes and nothing else:

        ecosystem_name  — canonical name, e.g. "drupal"
        osv_name        — OSV ecosystem string, e.g. "Packagist"
        dependabot_slug — Dependabot branch prefix, e.g. "drupal"
        name_re         — package name validation regex
        remote_base_url — HTTP base URL with no trailing slash
    """

    ecosystem_name: str
    osv_name: str
    dependabot_slug: str
    name_re: re.Pattern
    remote_base_url: str

    # ------------------------------------------------------------------
    # Internal HTTP helper
    # ------------------------------------------------------------------

    async def _post(self, method: str, payload: dict[str, Any]) -> Any:
        """POST to {remote_base_url}/{method} with JSON payload, return parsed body.

        Raises ApplicationError(non_retryable=True) on 404/410.
        Raises httpx.HTTPStatusError on other 4xx/5xx (Temporal will retry).
        """
        client = get_client()
        resp = await client.post(f"{self.remote_base_url}/{method}", json=payload, timeout=30.0)
        if resp.status_code in (404, 410):
            raise ApplicationError(
                f"Remote provider {self.ecosystem_name!r} returned {resp.status_code} for {method}",
                type="PackageNotFound",
                non_retryable=True,
            )
        resp.raise_for_status()
        if not resp.content:
            return None
        return resp.json()

    # ------------------------------------------------------------------
    # EcosystemProvider methods
    # ------------------------------------------------------------------

    async def fetch_metadata(self, package: str, old_version: str, new_version: str) -> PyPISignals:
        """POST fetch_metadata — request: {package, old_version, new_version}
        Response: PyPISignals fields (weekly_downloads, is_major_bump, package_description).
        """
        data = await self._post(
            "fetch_metadata",
            {
                "package": package,
                "old_version": old_version,
                "new_version": new_version,
            },
        )
        return PyPISignals(**(data or {}))

    async def fetch_release_age(self, package: str, new_version: str) -> ReleaseAgeSignals:
        """POST fetch_release_age — request: {package, new_version}
        Response: ReleaseAgeSignals fields (release_age_hours).
        """
        data = await self._post(
            "fetch_release_age",
            {
                "package": package,
                "new_version": new_version,
            },
        )
        return ReleaseAgeSignals(**(data or {}))

    async def fetch_maintainer(
        self, package: str, old_version: str, new_version: str
    ) -> MaintainerSignals:
        """POST fetch_maintainer — request: {package, old_version, new_version}
        Response: MaintainerSignals fields (maintainer_changed).
        """
        data = await self._post(
            "fetch_maintainer",
            {
                "package": package,
                "old_version": old_version,
                "new_version": new_version,
            },
        )
        return MaintainerSignals(**(data or {}))

    async def get_archive_url(
        self, client: httpx.AsyncClient, package: str, version: str
    ) -> tuple[str, str, str] | None:
        """POST get_archive_url — request: {package, version}
        Response: {"url": str, "filename": str, "checksum": str} or null (no archive).
        """
        data = await self._post("get_archive_url", {"package": package, "version": version})
        if not data:
            return None
        url = data["url"]
        validate_archive_url(url)
        return url, data.get("filename", f"{package}-{version}"), data.get("checksum", "")

    def extract_archive(self, archive_bytes: bytes, filename: str, dest: str) -> None:
        """Extract zip or tar.gz archives with path-traversal and zip-bomb protection.

        Remote providers return common archive formats; override this method if your
        service uses something else (e.g. a custom format).
        """
        dest_path = Path(dest)
        if filename.endswith(".zip"):
            self._extract_zip(archive_bytes, dest_path)
        else:
            self._extract_tar(archive_bytes, dest_path)

    def _extract_zip(self, data: bytes, dest: Path) -> None:
        total = 0
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for member in zf.infolist():
                unix_mode = (member.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(unix_mode):
                    raise ApplicationError(
                        f"Zip contains symlink entry: {member.filename}",
                        non_retryable=True,
                    )
                member_path = (dest / member.filename).resolve()
                if not str(member_path).startswith(str(dest)):
                    raise ApplicationError(
                        f"Zip path traversal attempt: {member.filename}",
                        non_retryable=True,
                    )
                total += member.file_size
                if total > MAX_EXTRACT_BYTES:
                    raise ApplicationError(
                        "Zip extraction size limit exceeded (possible zip bomb)",
                        non_retryable=True,
                    )
                zf.extract(member, dest)

    def _extract_tar(self, data: bytes, dest: Path) -> None:
        total = 0
        with tarfile.open(fileobj=io.BytesIO(data)) as tf:
            for member in tf.getmembers():
                if member.issym() or member.islnk():
                    raise ApplicationError(
                        f"Tar contains symlink/hardlink entry: {member.name}",
                        non_retryable=True,
                    )
                member_path = (dest / member.name).resolve()
                if not str(member_path).startswith(str(dest)):
                    raise ApplicationError(
                        f"Tar path traversal attempt: {member.name}",
                        non_retryable=True,
                    )
                total += member.size
                if total > MAX_EXTRACT_BYTES:
                    raise ApplicationError(
                        "Tar extraction size limit exceeded (possible zip bomb)",
                        non_retryable=True,
                    )
            tf.extractall(dest, filter="data")

    async def fetch_attestations(
        self, package: str, old_version: str, new_version: str
    ) -> AttestationSignals:
        """POST fetch_attestations — request: {package, old_version, new_version}
        Response: AttestationSignals fields.
        """
        data = await self._post(
            "fetch_attestations",
            {
                "package": package,
                "old_version": old_version,
                "new_version": new_version,
            },
        )
        return AttestationSignals(**(data or {}))

    async def fetch_release(self, package: str, old_version: str, version: str) -> ReleaseSignals:
        """POST fetch_release — request: {package, old_version, version}
        Response: ReleaseSignals fields.
        """
        data = await self._post(
            "fetch_release",
            {
                "package": package,
                "old_version": old_version,
                "version": version,
            },
        )
        return ReleaseSignals(**(data or {}))
