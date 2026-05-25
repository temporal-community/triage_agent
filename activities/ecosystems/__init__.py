"""
Ecosystem abstraction layer.

To add a new ecosystem:
  1. Create activities/ecosystems/{name}.py implementing EcosystemProvider
     (set ecosystem_name = "<key>" as a class attribute — get_provider() discovers it automatically)
  2. Add the ecosystem name to the Literal types in activities/models.py
  3. Add the branch slug to helpers/pr_parser.py's _DEPENDABOT_ECOSYSTEM_MAP
  4. Add a name-validation regex entry in api/webhook.py's _NAME_RE_BY_ECOSYSTEM
"""

from __future__ import annotations

import importlib
import inspect
import os
import pkgutil
import re
import stat
import tarfile
import urllib.parse
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Protocol

import httpx
from temporalio.exceptions import ApplicationError

import re as _re
from helpers.http import get_client

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
    ecosystem_name: str
    osv_name: str
    dependabot_slug: str  # Dependabot's internal branch prefix, e.g. "npm_and_yarn"
    name_re: re.Pattern  # package name validation regex for the webhook allowlist

    async def fetch_metadata(
        self, package: str, old_version: str, new_version: str
    ) -> PyPISignals: ...

    async def fetch_release_age(self, package: str, new_version: str) -> ReleaseAgeSignals: ...

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


_PROVIDERS: dict[str, EcosystemProvider] | None = None


def _build_provider_registry() -> dict[str, EcosystemProvider]:
    """Scan built-in providers then entry points for classes with an ecosystem_name attribute.

    Built-in providers: activities/ecosystems/*.py (pkgutil scan).
    External plugins: declare an entry point in group "dependency_scout.ecosystems":
        [project.entry-points."dependency_scout.ecosystems"]
        my_ecosystem = "my_package:MyProvider"

    Called lazily on first get_provider() call to avoid circular imports at
    module load time (providers import helpers from this same __init__.py).
    Built-in providers take precedence over plugins with the same ecosystem_name.
    """
    import activities.ecosystems as _pkg

    registry: dict[str, EcosystemProvider] = {}

    for mod_info in pkgutil.iter_modules(_pkg.__path__, prefix="activities.ecosystems."):
        mod = importlib.import_module(mod_info.name)
        for _, obj in inspect.getmembers(mod, inspect.isclass):
            name = getattr(obj, "ecosystem_name", None)
            if name and obj.__module__ == mod_info.name:
                registry[name] = obj()

    try:
        from importlib.metadata import entry_points

        for ep in entry_points(group="dependency_scout.ecosystems"):
            try:
                cls = ep.load()
                name = getattr(cls, "ecosystem_name", None)
                if name and name not in registry:
                    registry[name] = cls()
            except Exception:  # noqa: BLE001
                pass
    except Exception:  # noqa: BLE001
        pass

    return registry


def get_provider(ecosystem: str) -> EcosystemProvider:
    global _PROVIDERS
    if _PROVIDERS is None:
        _PROVIDERS = _build_provider_registry()
    if ecosystem not in _PROVIDERS:
        raise ValueError(f"Unknown ecosystem: {ecosystem!r}")
    return _PROVIDERS[ecosystem]


def get_dependabot_slug_map() -> dict[str, str]:
    """Return {dependabot_slug: ecosystem_name} built from provider attributes."""
    global _PROVIDERS
    if _PROVIDERS is None:
        _PROVIDERS = _build_provider_registry()
    return {p.dependabot_slug: name for name, p in _PROVIDERS.items()}


def get_name_re(ecosystem: str) -> re.Pattern | None:
    """Return the package name validation regex for this ecosystem, or None."""
    global _PROVIDERS
    if _PROVIDERS is None:
        _PROVIDERS = _build_provider_registry()
    p = _PROVIDERS.get(ecosystem)
    return p.name_re if p is not None else None


# ---------------------------------------------------------------------------
# Shared utilities used by multiple providers
# ---------------------------------------------------------------------------

ALLOWED_CDN_HOSTS: frozenset[str] = frozenset(
    {
        "files.pythonhosted.org",
        "registry.npmjs.org",
        "rubygems.org",
        "repo1.maven.org",
        "codeload.github.com",  # Composer archives — GitHub's archive CDN (no redirect)
        "api.nuget.org",
        "static.crates.io",
        "proxy.golang.org",
    }
)


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
        return int(new.split(".")[0].lstrip("vV")) > int(old.split(".")[0].lstrip("vV"))
    except (ValueError, IndexError):
        return False


_PRE_RE = _re.compile(r"(a|b|rc|alpha|beta|dev|pre|preview|post)[\d]*$", _re.IGNORECASE)


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

    majors: set[int] = {m for v in stable if (m := _major(v)) is not None}
    latest_major = max(majors)

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


_GITHUB_RE = re.compile(r"github\.com[:/]([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?(?:[/?#]|$)")
# npm shorthand: "github:owner/repo" — explicit, unambiguous
_GITHUB_SHORTHAND_RE = re.compile(r"^github:([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?$")
_GITLAB_RE = re.compile(r"gitlab\.com[:/]([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?(?:[/?#]|$)")
# Captures owner/repo after any host separator
_VCS_OWNER_REPO_RE = re.compile(r"[:/]([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?(?:[/?#]|$)")


def parse_vcs_repo(url: str) -> tuple[str, str] | None:
    """Return (platform, 'owner/repo') for a known platform URL, or None.

    Detected platforms: github, gitlab (gitlab.com and GITLAB_BASE_URL self-hosted).
    """
    if not url:
        return None
    m = _GITHUB_RE.search(url)
    if m:
        return ("github", m.group(1))
    m = _GITHUB_SHORTHAND_RE.match(url)
    if m:
        return ("github", m.group(1))
    # Self-hosted GitLab (checked before gitlab.com to allow custom domains)
    custom_base = os.environ.get("GITLAB_BASE_URL", "").rstrip("/")
    if custom_base and "://" in custom_base:
        custom_host = custom_base.split("://", 1)[1]
        if custom_host and custom_host in url:
            after_host = url.split(custom_host, 1)[1]
            m = _VCS_OWNER_REPO_RE.match(after_host)
            if m:
                return ("gitlab", m.group(1))
    m = _GITLAB_RE.search(url)
    if m:
        return ("gitlab", m.group(1))
    return None


def parse_github_repo(url: str) -> str | None:
    """Extract 'owner/repo' from any GitHub URL variant, or None. Legacy wrapper."""
    if not url:
        return None
    m = _GITHUB_RE.search(url)
    if m:
        return m.group(1)
    m = _GITHUB_SHORTHAND_RE.match(url)
    return m.group(1) if m else None


async def fetch_vcs_release(
    platform: str, owner: str, repo: str, version: str, token: str | None
) -> dict | None:
    """Return a normalised release dict for the given version, or None.

    Fields are normalised to GitHub shape: created_at, published_at, body, author.login.
    """
    if platform == "github":
        headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            client = get_client()
            for tag in (f"v{version}", version):
                resp = await client.get(
                    f"https://api.github.com/repos/{owner}/{repo}/releases/tags/{tag}",
                    headers=headers,
                    timeout=10.0,
                )
                if resp.status_code == 200:
                    return resp.json()
        except Exception:  # noqa: BLE001
            pass
        return None

    if platform == "gitlab":
        import urllib.parse as _urlparse

        base_url = os.environ.get("GITLAB_BASE_URL", "https://gitlab.com").rstrip("/")
        encoded = _urlparse.quote(f"{owner}/{repo}", safe="")
        gl_token = token or os.environ.get("GITLAB_TOKEN")
        headers = {}
        if gl_token:
            headers["Authorization"] = f"Bearer {gl_token}"
        try:
            client = get_client()
            for tag in (f"v{version}", version):
                resp = await client.get(
                    f"{base_url}/api/v4/projects/{encoded}/releases/{_urlparse.quote(tag, safe='')}",
                    headers=headers,
                    timeout=10.0,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    # Normalise GitLab release fields to GitHub shape
                    released_at = data.get("released_at", "")
                    return {
                        "created_at": released_at,
                        "published_at": released_at,
                        "body": data.get("description", ""),
                        "author": {"login": (data.get("author") or {}).get("username", "")},
                    }
        except Exception:  # noqa: BLE001
            pass
        return None

    return None


# Backward-compat alias used by older callers and tests
async def fetch_github_release(
    owner: str, repo: str, version: str, token: str | None
) -> dict | None:
    return await fetch_vcs_release("github", owner, repo, version, token)


async def fetch_vcs_tag_signature(
    platform: str, owner: str, repo: str, version: str, token: str | None
) -> bool | None:
    """Return True/False for verified/unverified annotated tag signature, None if absent.

    GitLab does not expose server-side signature verification — always returns None.
    For GitHub, lightweight tags cannot carry a signature and also return None.
    """
    if platform != "github":
        return None
    headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        client = get_client()
        for tag_name in (f"v{version}", version):
            ref_resp = await client.get(
                f"https://api.github.com/repos/{owner}/{repo}/git/refs/tags/{tag_name}",
                headers=headers,
                timeout=10.0,
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
                timeout=10.0,
            )
            if tag_resp.status_code != 200:
                return None
            verification = tag_resp.json().get("verification") or {}
            return bool(verification.get("verified"))
    except Exception:  # noqa: BLE001
        pass
    return None


# Backward-compat alias
async def fetch_tag_signature(
    owner: str, repo: str, version: str, token: str | None
) -> bool | None:
    return await fetch_vcs_tag_signature("github", owner, repo, version, token)


def build_release_signals(
    release: dict,
    registry_time: datetime | None = None,
    tag_signature_verified: bool | None = None,
    old_tag_signature_verified: bool | None = None,
) -> ReleaseSignals:
    """Convert a normalised release dict into structured ReleaseSignals.

    Both GitHub and GitLab releases are pre-normalised to GitHub field names by
    fetch_vcs_release before reaching this function.
    """
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
            delta = (
                parse_upload_time(published_at) - parse_upload_time(created_at)
            ).total_seconds()
            possible_rerelease = delta > 86_400  # drafted >24h before publishing
        except Exception:  # noqa: BLE001
            pass

    raw_body = release.get("body") or ""
    body: str | None = None
    if raw_body:
        body = (
            (raw_body[:3000] + "\n[release notes truncated]") if len(raw_body) > 3000 else raw_body
        )

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


async def fetch_vcs_account_age(platform: str, owner: str) -> int | None:
    """Return age in days of a user/org account on the given platform, or None."""
    if platform == "github":
        token = os.environ.get("GITHUB_TOKEN")
        if not token:
            return None
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
        }
        try:
            client = get_client()
            resp = await client.get(
                f"https://api.github.com/users/{owner}", headers=headers, timeout=10.0
            )
            if resp.status_code == 200:
                created_at = resp.json().get("created_at", "")
                if created_at:
                    created = parse_upload_time(created_at)
                    return max(0, (datetime.now(timezone.utc) - created).days)
        except Exception:  # noqa: BLE001
            pass
        return None

    if platform == "gitlab":
        token = os.environ.get("GITLAB_TOKEN")
        if not token:
            return None
        base_url = os.environ.get("GITLAB_BASE_URL", "https://gitlab.com").rstrip("/")
        headers = {"Authorization": f"Bearer {token}"}
        try:
            client = get_client()
            resp = await client.get(
                f"{base_url}/api/v4/users",
                headers=headers,
                params={"username": owner},
                timeout=10.0,
            )
            if resp.status_code == 200 and resp.json():
                created_at = resp.json()[0].get("created_at", "")
                if created_at:
                    created = parse_upload_time(created_at)
                    return max(0, (datetime.now(timezone.utc) - created).days)
        except Exception:  # noqa: BLE001
            pass
        return None

    return None


async def fetch_vcs_ci_workflow_changes(
    platform: str, owner: str, repo: str, since_days: int = 30
) -> int | None:
    """Return days since the most recent commit touching .github/workflows/, or None.

    None means either no changes in the window, no GitHub token, or an error.
    A low value (e.g. < 7) means the CI pipeline was modified just before the release —
    a key signal for GhostAction / TeamPCP / tj-actions style supply chain attacks.
    Only implemented for GitHub (GitLab CI is in .gitlab-ci.yml, not a standard path).
    """
    if platform != "github":
        return None
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        return None
    since = (datetime.now(timezone.utc) - timedelta(days=since_days)).isoformat()
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
    }
    try:
        client = get_client()
        resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/commits",
            headers=headers,
            params={"path": ".github/workflows", "since": since, "per_page": "1"},
            timeout=10.0,
        )
        if resp.status_code != 200:
            return None
        commits = resp.json()
        if not commits:
            return None
        commit_date_raw = commits[0].get("commit", {}).get("committer", {}).get("date", "")
        if not commit_date_raw:
            return None
        commit_date = parse_upload_time(commit_date_raw)
        return max(0, (datetime.now(timezone.utc) - commit_date).days)
    except Exception:  # noqa: BLE001
        return None


# Backward-compat alias
async def fetch_github_account_age(owner: str) -> int | None:
    return await fetch_vcs_account_age("github", owner)


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


def safe_tar_extractall(tf: tarfile.TarFile, dest: str) -> None:
    """Extract a tarball with path-traversal and decompression-bomb protection.

    filter="data" (Python 3.12+) handles: absolute paths, ../  traversal, device
    files, and symlink escapes. This wrapper adds a cumulative size cap so a
    maximally-compressed archive (e.g. 19.9 MB compressed → many GB uncompressed)
    cannot exhaust disk space.
    """
    total_extracted = 0
    for member in tf.getmembers():
        total_extracted += max(member.size, 0)
        if total_extracted > MAX_EXTRACT_BYTES:
            raise ApplicationError(
                "Tar extraction size limit exceeded (possible tar bomb)",
                non_retryable=True,
            )
        tf.extract(member, dest, filter="data")
