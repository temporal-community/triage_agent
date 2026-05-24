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

import os
import re
import stat
import urllib.parse
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Protocol

import httpx
from temporalio.exceptions import ApplicationError

import re as _re

from activities.models import (
    AttestationSignals,
    MaintainerSignals,
    PyPISignals,
    ReleaseAgeSignals,
    ReleaseSignals,
    VersionLineSignals,
)

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

    async def fetch_attestations(
        self, package: str, old_version: str, new_version: str
    ) -> AttestationSignals: ...

    async def fetch_release(
        self, package: str, old_version: str, version: str
    ) -> ReleaseSignals: ...


def get_provider(ecosystem: str) -> EcosystemProvider:
    from activities.ecosystems.composer import ComposerProvider
    from activities.ecosystems.maven import MavenProvider
    from activities.ecosystems.npm import NpmProvider
    from activities.ecosystems.pip import PipProvider
    from activities.ecosystems.rubygems import RubyGemsProvider

    providers: dict[str, EcosystemProvider] = {
        "pip": PipProvider(),
        "npm": NpmProvider(),
        "rubygems": RubyGemsProvider(),
        "maven": MavenProvider(),
        "composer": ComposerProvider(),
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
    "repo1.maven.org",
    "codeload.github.com",   # Composer archives — GitHub's archive CDN (no redirect)
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


_PRE_RE = _re.compile(
    r"(a|b|rc|alpha|beta|dev|pre|preview|post)[\d]*$", _re.IGNORECASE
)


def detect_stale_version_line(
    all_versions: list[str],
    new_version: str,
    cutoff_days: int = 730,
    release_dates: dict[str, datetime] | None = None,
) -> VersionLineSignals:
    """Return VersionLineSignals indicating whether new_version patches a stale major line.

    A version line is considered stale when the bump's major version is lower than the
    highest stable major and that highest major had a release within the last *cutoff_days*.

    release_dates maps version string → datetime (UTC) for the *cutoff_days* check.
    If omitted, only the version numbers are used (no recency check — more conservative).
    """
    def _major(v: str) -> int | None:
        part = v.lstrip("vV").split(".")[0]
        return int(part) if part.isdigit() else None

    def _is_prerelease(v: str) -> bool:
        return bool(_PRE_RE.search(v))

    stable = [v for v in all_versions if not _is_prerelease(v) and _major(v) is not None]
    if not stable:
        return VersionLineSignals()

    bump_major = _major(new_version)
    if bump_major is None:
        return VersionLineSignals()

    majors = {_major(v) for v in stable}
    latest_major = max(majors)  # type: ignore[type-var]

    if bump_major >= latest_major:
        return VersionLineSignals(bump_major=bump_major, latest_major=latest_major)

    # bump is targeting an older major — check if the latest major is actively maintained
    if release_dates:
        cutoff = datetime.now(timezone.utc) - timedelta(days=cutoff_days)
        latest_major_versions = [v for v in stable if _major(v) == latest_major]
        latest_major_active = any(
            release_dates.get(v, datetime.min.replace(tzinfo=timezone.utc)) >= cutoff
            for v in latest_major_versions
        )
        if not latest_major_active:
            return VersionLineSignals(bump_major=bump_major, latest_major=latest_major)

    return VersionLineSignals(
        stale_version_line=True,
        bump_major=bump_major,
        latest_major=latest_major,
    )


def parse_upload_time(raw: str) -> datetime:
    raw = raw.replace("Z", "+00:00")
    dt = datetime.fromisoformat(raw)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


_GITHUB_RE = re.compile(
    r"github\.com[:/]([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?(?:[/?#]|$)"
)
# npm shorthand: "github:owner/repo" — explicit, unambiguous
_GITHUB_SHORTHAND_RE = re.compile(
    r"^github:([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?$"
)


def parse_github_repo(url: str) -> str | None:
    """Extract 'owner/repo' from any GitHub URL variant, or None."""
    if not url:
        return None
    m = _GITHUB_RE.search(url)
    if m:
        return m.group(1)
    m = _GITHUB_SHORTHAND_RE.match(url)
    return m.group(1) if m else None


async def fetch_github_release(
    owner: str, repo: str, version: str, token: str | None
) -> dict | None:
    """Return the GitHub release JSON for the given version, trying v-prefixed tag first."""
    headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            for tag in (f"v{version}", version):
                resp = await client.get(
                    f"https://api.github.com/repos/{owner}/{repo}/releases/tags/{tag}",
                    headers=headers,
                )
                if resp.status_code == 200:
                    return resp.json()
    except Exception:  # noqa: BLE001
        pass
    return None


async def fetch_tag_signature(
    owner: str, repo: str, version: str, token: str | None
) -> bool | None:
    """Return True/False for verified/unverified annotated tag signature, None if absent.

    Lightweight tags cannot carry a signature and always return None.
    GitHub validates the GPG/SSH signature server-side; the `verified` field
    reflects whether it trusts the key.
    """
    headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            for tag_name in (f"v{version}", version):
                ref_resp = await client.get(
                    f"https://api.github.com/repos/{owner}/{repo}/git/refs/tags/{tag_name}",
                    headers=headers,
                )
                if ref_resp.status_code != 200:
                    continue
                data = ref_resp.json()
                # A prefix match returns an array; an exact match returns a single object.
                if isinstance(data, list):
                    matches = [r for r in data if r.get("ref") == f"refs/tags/{tag_name}"]
                    if not matches:
                        continue
                    data = matches[0]
                obj = data.get("object", {})
                if obj.get("type") != "tag":
                    # Lightweight tag — points directly to a commit, no tag signature
                    return None
                sha = obj.get("sha", "")
                if not sha:
                    return None
                tag_resp = await client.get(
                    f"https://api.github.com/repos/{owner}/{repo}/git/tags/{sha}",
                    headers=headers,
                )
                if tag_resp.status_code != 200:
                    return None
                verification = tag_resp.json().get("verification") or {}
                return bool(verification.get("verified"))
    except Exception:  # noqa: BLE001
        pass
    return None


def build_release_signals(
    release: dict,
    registry_time: datetime | None = None,
    tag_signature_verified: bool | None = None,
    old_tag_signature_verified: bool | None = None,
) -> ReleaseSignals:
    """Convert a GitHub release API response into structured ReleaseSignals."""
    author_login: str = (release.get("author") or {}).get("login") or ""
    release_is_automated = "[bot]" in author_login

    skew_minutes: float | None = None
    created_at = release.get("created_at", "")
    if created_at and registry_time is not None:
        try:
            gh_time = parse_upload_time(created_at)
            skew_minutes = round(abs((gh_time - registry_time).total_seconds()) / 60, 1)
        except Exception:  # noqa: BLE001
            pass

    possible_rerelease = False
    published_at = release.get("published_at", "")
    if created_at and published_at and created_at != published_at:
        try:
            delta = (parse_upload_time(published_at) - parse_upload_time(created_at)).total_seconds()
            possible_rerelease = delta > 86_400  # drafted >24h before publishing
        except Exception:  # noqa: BLE001
            pass

    raw_body = release.get("body") or ""
    body: str | None = None
    if raw_body:
        body = (raw_body[:3000] + "\n[release notes truncated]") if len(raw_body) > 3000 else raw_body

    # Signing regression: old version had a verified tag, new version doesn't
    tag_was_previously_signed = (
        old_tag_signature_verified is True and tag_signature_verified is not True
    )

    return ReleaseSignals(
        github_release_exists=True,
        release_author=author_login or None,
        release_is_automated=release_is_automated,
        timestamp_skew_minutes=skew_minutes,
        possible_rerelease=possible_rerelease,
        release_body=body,
        tag_signature_verified=tag_signature_verified,
        tag_was_previously_signed=tag_was_previously_signed,
    )


async def fetch_github_account_age(owner: str) -> int | None:
    """Return age in days of a GitHub user/org account, or None if unavailable.

    Requires GITHUB_TOKEN — skipped without one to avoid unauthenticated rate limits.
    """
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        return None
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"https://api.github.com/users/{owner}", headers=headers)
            if resp.status_code == 200:
                created_at = resp.json().get("created_at", "")
                if created_at:
                    created = parse_upload_time(created_at)
                    return max(0, (datetime.now(timezone.utc) - created).days)
    except Exception:  # noqa: BLE001
        pass
    return None


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
