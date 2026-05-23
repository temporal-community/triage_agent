"""
Ecosystem abstraction layer.

To add a new ecosystem:
  1. Create activities/ecosystems/{name}.py implementing EcosystemProvider
  2. Add one entry to the registry in get_provider()
  3. Add the ecosystem name to the Literal types in activities/models.py
  4. Add the branch slug to helpers/pr_parser.py's _DEPENDABOT_ECOSYSTEM_MAP
  5. Add a name-validation regex entry in api/webhook.py's _NAME_RE_BY_ECOSYSTEM
"""
from __future__ import annotations

import stat
import urllib.parse
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

import httpx
from temporalio.exceptions import ApplicationError

from activities.models import MaintainerSignals, PyPISignals, ReleaseAgeSignals

MAX_EXTRACT_BYTES = 100 * 1024 * 1024  # zip bomb guard


class EcosystemProvider(Protocol):
    osv_name: str

    async def fetch_metadata(
        self, package: str, old_version: str, new_version: str
    ) -> PyPISignals: ...

    async def fetch_release_age(
        self, package: str, new_version: str
    ) -> ReleaseAgeSignals: ...

    async def fetch_maintainer(
        self, package: str, old_version: str, new_version: str
    ) -> MaintainerSignals: ...

    async def get_archive_url(
        self, client: httpx.AsyncClient, package: str, version: str
    ) -> tuple[str, str, str] | None: ...

    def extract_archive(self, archive_bytes: bytes, filename: str, dest: str) -> None: ...


def get_provider(ecosystem: str) -> EcosystemProvider:
    from activities.ecosystems.npm import NpmProvider
    from activities.ecosystems.pip import PipProvider
    from activities.ecosystems.rubygems import RubyGemsProvider

    providers: dict[str, EcosystemProvider] = {
        "pip": PipProvider(),
        "npm": NpmProvider(),
        "rubygems": RubyGemsProvider(),
    }
    if ecosystem not in providers:
        raise ValueError(f"Unknown ecosystem: {ecosystem!r}")
    return providers[ecosystem]


# ---------------------------------------------------------------------------
# Shared utilities used by multiple providers
# ---------------------------------------------------------------------------

ALLOWED_CDN_HOSTS: frozenset[str] = frozenset({
    "files.pythonhosted.org",
    "registry.npmjs.org",
    "rubygems.org",
})


def validate_archive_url(url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        raise ApplicationError(
            f"Insecure archive URL scheme '{parsed.scheme}' — only https is allowed",
            non_retryable=True,
        )
    if parsed.netloc not in ALLOWED_CDN_HOSTS:
        raise ApplicationError(
            f"Untrusted archive host '{parsed.netloc}' — "
            f"expected one of {sorted(ALLOWED_CDN_HOSTS)}",
            non_retryable=True,
        )


def is_major(old: str, new: str) -> bool:
    try:
        return int(new.split(".")[0]) > int(old.split(".")[0])
    except (ValueError, IndexError):
        return False


def parse_upload_time(raw: str) -> datetime:
    raw = raw.replace("Z", "+00:00")
    dt = datetime.fromisoformat(raw)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def safe_zip_extractall(zf: zipfile.ZipFile, dest: Path) -> None:
    """Extract a zip with path-traversal, symlink, and zip-bomb protection."""
    total_extracted = 0
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
        total_extracted += member.file_size
        if total_extracted > MAX_EXTRACT_BYTES:
            raise ApplicationError(
                "Zip extraction size limit exceeded (possible zip bomb)",
                non_retryable=True,
            )
        zf.extract(member, dest)
