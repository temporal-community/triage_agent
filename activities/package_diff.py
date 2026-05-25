"""
Activity: compute a security-focused diff between two package versions.
Downloads both archives, extracts them, and returns a PackageDiffChecks model.
Archive format and CDN host are fully delegated to the ecosystem provider.
"""

from __future__ import annotations

import asyncio
import base64
import difflib
import hashlib
import hmac
import json
import os
import re
import tempfile
from collections.abc import Callable
from pathlib import Path

import httpx
from temporalio import activity
from temporalio.exceptions import ApplicationError

from ecosystems import (
    fetch_vcs_file_at_tag,
    get_provider,
    parse_vcs_repo,
    validate_archive_url,
)
from models import PackageDiffChecks
from helpers.cache import ActivityCache
from helpers.http import get_client
from detections import (
    NET_CALL_PATTERNS as _NET_CALL_PATTERNS,
    OBFUSCATION_PATTERNS as _OBFUSCATION_PATTERNS,
    OBFUSCATION_LINE_THRESHOLD as _OBFUSCATION_LINE_THRESHOLD,
    GZIP_B64_RE as _GZIP_B64_RE,
    GZIP_B64_EXTENSIONS,
    ZERO_WIDTH_RE as _ZERO_WIDTH_RE,
    ZERO_WIDTH_SOURCE_EXTENSIONS as _ZERO_WIDTH_SOURCE_EXTENSIONS,
    PERSISTENCE_PATTERNS as _PERSISTENCE_PATTERNS,
    NPM_CRED_READ_RE as _NPM_CRED_READ_RE,
    NPM_PUBLISH_RE as _NPM_PUBLISH_RE,
    SUSPICIOUS_PACKAGE_FILES as _SUSPICIOUS_PACKAGE_FILES,
    SUSPICIOUS_PACKAGE_PREFIXES as _SUSPICIOUS_PACKAGE_PREFIXES,
    DANGEROUS_BINARY_SUFFIXES,
    INSTALL_HOOK_NAMES,
    NPM_INSTALL_SCRIPTS,
)

_cache: ActivityCache = ActivityCache()  # archive contents are immutable after publish

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_DOWNLOAD_BYTES = 20 * 1024 * 1024  # 20 MB
MAX_DIFF_BYTES = 100 * 1024  # 100 KB

NOISE_DIRS = {
    ".dist-info",
    "__pycache__",
    ".egg-info",
    "node_modules",
    ".nyc_output",
    "coverage",
    "META-INF",
}
NOISE_SUFFIXES = {".pyc", ".pyo", ".rbc"}  # .rbc = Ruby bytecode cache
NOISE_FILENAMES = {
    "RECORD",
    "WHEEL",
    "METADATA",
    "INSTALLER",
    "package-lock.json",
    "yarn.lock",
    "npm-shrinkwrap.json",
}

HIGH_RISK_NAMES = {
    "setup.py",
    "setup.cfg",
    "pyproject.toml",
    "__init__.py",
    "package.json",
    "index.js",
    "install.js",
    "postinstall.js",
    "preinstall.js",
    "Rakefile",
    "Gemfile",
    "Cargo.toml",
    "go.sum",
    "pom.xml",
    "composer.json",
    # AI editor config files — no legitimate reason to ship these in a package archive
    ".cursorrules",
    "CLAUDE.md",
}
HIGH_RISK_SUFFIXES = {".pth", ".gemspec"}

# Extensions that are legitimately binary and don't need content inspection.
# Files with these extensions are skipped for the binary_data_added check.
_EXPECTED_BINARY_EXTENSIONS = DANGEROUS_BINARY_SUFFIXES | {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".webp",
    ".bmp",
    ".tiff",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".otf",
    ".zip",
    ".tar",
    ".gz",
    ".bz2",
    ".xz",
    ".pdf",
    ".db",
    ".sqlite",
    ".sqlite3",
    ".mp3",
    ".mp4",
    ".wav",
    ".avi",
    ".mov",
    ".exe",
    ".bin",
    ".dat",
}

# npm dependency version prefixes that bypass the registry (git/URL sourced)
_GIT_DEP_PREFIXES = ("github:", "git+", "git://", "bitbucket:", "gitlab:", "file:")
_HTTP_DEP_RE = re.compile(r"^https?://")

# pip git-URL dependency patterns (PEP 508 URL reqs and -e editable installs)
_PIP_GIT_DEP_RE = re.compile(r"git\+https?://|git\+ssh://|\s@\s+https?://\S+\.git\b", re.IGNORECASE)

# Cargo.toml inline table git dependency: some-crate = { git = "https://..." }
_CARGO_GIT_DEP_RE = re.compile(r'\bgit\s*=\s*["\']https?://', re.IGNORECASE)

# Files compared between archive and git tag to detect XZ-style build-artifact tampering.
# Limited to files that: (a) are high-value attack targets, (b) have stable content between
# registry publish and git commit (unlike auto-generated files or version bumps).
_ARTIFACT_CHECK_NAMES: frozenset[str] = frozenset(
    {"setup.py", "__init__.py", "index.js", "index.ts", "Cargo.toml"}
)

# Lines that consist only of a version string change (e.g. __version__ = "1.2.3" → "1.2.4").
# Filtered out before counting unexplained new lines in the artifact/source diff.
_VERSION_LINE_RE = re.compile(
    r"""^\s*(?:__version__|version|VERSION)\s*=\s*['"][\d.]+['"]\s*$""", re.IGNORECASE
)

# Minimum new lines in archive (beyond version changes) to flag as a mismatch.
_ARTIFACT_MISMATCH_THRESHOLD = 5


# ---------------------------------------------------------------------------
# Activity entry point
# ---------------------------------------------------------------------------


@activity.defn(name="activities.package_diff.compute")
async def compute(
    ecosystem: str, package: str, old_version: str, new_version: str
) -> PackageDiffChecks:
    """Download both package archives from the registry, extract them, and diff them for suspicious changes such as new install hooks, obfuscated code, outbound network calls, and binary payloads.

    Returns a ``PackageDiffChecks`` with a human-readable diff summary and boolean flags for each category of risk."""
    key = (ecosystem, package, old_version, new_version)
    if (hit := _cache.get(key)) is not None:
        activity.logger.debug("package_diff cache hit: %s %s→%s", package, old_version, new_version)
        return hit
    activity.logger.info(f"Computing package diff for {package} {old_version} -> {new_version}")

    provider = get_provider(ecosystem)

    client = get_client()
    old_info, new_info = await asyncio.gather(
        provider.get_archive_url(client, package, old_version),
        provider.get_archive_url(client, package, new_version),
    )

    if old_info is None or new_info is None:
        return PackageDiffChecks(diff_summary="[sdist not available]", diff_size_bytes=0)

    old_url, old_filename, old_integrity = old_info
    new_url, new_filename, new_integrity = new_info

    activity.heartbeat("downloading archives")
    old_bytes, new_bytes = await asyncio.gather(
        _download(client, old_url, old_integrity, heartbeat=activity.heartbeat),
        _download(client, new_url, new_integrity, heartbeat=activity.heartbeat),
    )

    if old_bytes is None or new_bytes is None:
        return PackageDiffChecks(
            diff_summary="[download aborted: archive exceeds 20 MB size limit]",
            diff_size_bytes=0,
        )

    # Extraction and diff are CPU/blocking I/O — run in a thread.
    activity.heartbeat("extracting and diffing")
    (
        diff_summary,
        install_script_added,
        install_script_changed,
        new_dep_count,
        net_calls,
        binary_data,
        git_url_dep,
        obfuscated,
        persistence,
        worm,
        lockfile_downgraded,
        artifact_files,
    ) = await asyncio.to_thread(
        _extract_and_diff, old_bytes, old_filename, new_bytes, new_filename, provider
    )

    # XZ-style check: compare archive files against git tag source (async, runs after thread).
    activity.heartbeat("checking artifact/source integrity")
    artifact_mismatch, mismatch_files = await _compare_artifact_to_source(
        client, ecosystem, package, new_version, artifact_files
    )

    result = PackageDiffChecks(
        diff_summary=diff_summary,
        diff_size_bytes=len(diff_summary.encode()),
        install_script_added=install_script_added,
        install_script_changed=install_script_changed,
        new_dependency_count=new_dep_count,
        network_calls_in_lib=net_calls,
        binary_data_added=binary_data,
        git_url_dependency_added=git_url_dep,
        obfuscated_code=obfuscated,
        persistence_mechanism_added=persistence,
        worm_propagation_pattern=worm,
        lockfile_integrity_downgraded=lockfile_downgraded,
        artifact_source_mismatch=artifact_mismatch,
        artifact_source_mismatch_files=mismatch_files,
    )
    _cache.set(key, result)
    return result


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


async def _download(
    client: httpx.AsyncClient,
    url: str,
    integrity: str,
    heartbeat: Callable | None = None,
) -> bytes | None:
    """Download *url*, verify integrity, return bytes or None if oversized.

    integrity formats accepted:
      - 64-char hex string        → SHA-256 (PyPI digests.sha256)
      - 'sha512-<base64>'         → SHA-512 SRI (npm dist.integrity)
      - ''                        → no verification

    heartbeat is called every ~1 MB so the Temporal worker can prove liveness
    to the server during slow downloads.
    """
    validate_archive_url(url)

    chunks: list[bytes] = []
    total = 0
    next_heartbeat_at = 1024 * 1024  # pulse every 1 MB
    async with client.stream("GET", url) as resp:
        resp.raise_for_status()
        async for chunk in resp.aiter_bytes(chunk_size=65536):
            total += len(chunk)
            if total > MAX_DOWNLOAD_BYTES:
                return None
            chunks.append(chunk)
            if heartbeat and total >= next_heartbeat_at:
                heartbeat(f"downloaded {total // 1024} KB from {url}")
                next_heartbeat_at += 1024 * 1024
    data = b"".join(chunks)

    if integrity:
        _verify_integrity(data, integrity, url)

    return data


def _verify_integrity(data: bytes, integrity: str, url: str) -> None:
    """Verify data against a SHA-256 hex digest or a SHA-512 SRI string."""
    if integrity.startswith("sha512-"):
        expected_bytes = base64.b64decode(integrity[len("sha512-") :])
        actual_bytes = hashlib.sha512(data).digest()
        if not hmac.compare_digest(actual_bytes, expected_bytes):
            raise ApplicationError(
                f"SHA-512 integrity check failed for {url}",
                non_retryable=True,
            )
    elif len(integrity) == 64:
        actual = hashlib.sha256(data).hexdigest()
        if not hmac.compare_digest(actual, integrity):
            raise ApplicationError(
                f"SHA-256 mismatch for {url}: expected {integrity}, got {actual}",
                non_retryable=True,
            )
    else:
        activity.logger.warning(f"Unrecognised integrity format for {url}, skipping check")


# ---------------------------------------------------------------------------
# Synchronous extraction + diff (runs in asyncio.to_thread)
# ---------------------------------------------------------------------------


def _extract_and_diff(
    old_bytes: bytes,
    old_filename: str,
    new_bytes: bytes,
    new_filename: str,
    provider,
) -> tuple[str, bool, bool, int, bool, bool, bool, bool, bool, bool, bool, dict[str, str]]:
    try:
        with tempfile.TemporaryDirectory() as old_dir, tempfile.TemporaryDirectory() as new_dir:
            provider.extract_archive(old_bytes, old_filename, old_dir)
            provider.extract_archive(new_bytes, new_filename, new_dir)

            # Check package-lock.json before noise filtering strips it from the map
            lockfile_downgraded = False
            old_locks = list(Path(old_dir).rglob("package-lock.json"))
            new_locks = list(Path(new_dir).rglob("package-lock.json"))
            if old_locks and new_locks:
                lockfile_downgraded = _npm_lockfile_integrity_downgraded(old_locks[0], new_locks[0])

            old_map = _get_file_map(old_dir)
            new_map = _get_file_map(new_dir)
            diff_result = _build_diff(old_map, new_map)

            # Capture high-signal file contents for XZ-style artifact/source comparison.
            # Done here while the temp dir is still alive — avoids a second extraction.
            artifact_files: dict[str, str] = {
                rel: _read_text(path)
                for rel, path in new_map.items()
                if Path(rel).name in _ARTIFACT_CHECK_NAMES
            }

            return (*diff_result, lockfile_downgraded, artifact_files)
    except Exception as exc:  # noqa: BLE001
        return (
            f"[extraction error: {exc}]",
            False,
            False,
            0,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            {},
        )


def _is_noise(rel: str) -> bool:
    """Return True if this path should be excluded from the diff."""
    parts = Path(rel).parts
    for part in parts[:-1]:
        if part in NOISE_DIRS:
            return True
        if part.endswith(".egg-info") or part.endswith(".dist-info"):
            return True
    name = parts[-1] if parts else ""
    if name in NOISE_FILENAMES:
        return True
    if Path(name).suffix in NOISE_SUFFIXES:
        return True
    if Path(name).suffix in HIGH_RISK_SUFFIXES:
        return False  # explicitly keep high-signal suffixes like .pth
    return False


def _get_file_map(base_dir: str) -> dict[str, Path]:
    """
    Walk *base_dir* and return {relative_path_str: absolute_Path}.

    For sdists the top-level directory (e.g. ``requests-2.32.0/``) is stripped
    so that paths are comparable across versions.
    """
    base = Path(base_dir)
    result: dict[str, Path] = {}

    all_files = list(base.rglob("*"))
    top_level_dirs = {p.relative_to(base).parts[0] for p in all_files if p.relative_to(base).parts}
    strip_top = len(top_level_dirs) == 1

    for path in all_files:
        if not path.is_file():
            continue
        rel = path.relative_to(base)
        parts = rel.parts
        if strip_top and len(parts) > 1:
            rel_str = str(Path(*parts[1:]))
        elif strip_top and len(parts) == 1:
            continue
        else:
            rel_str = str(rel)

        if _is_noise(rel_str):
            continue
        result[rel_str] = path

    return result


_REQUIREMENTS_NAMES = frozenset(
    {
        "requirements.txt",
        "requirements-dev.txt",
        "requirements-test.txt",
        "requirements-prod.txt",
        "requirements-base.txt",
    }
)


def _build_diff(
    old_map: dict[str, Path], new_map: dict[str, Path]
) -> tuple[str, bool, bool, int, bool, bool, bool, bool, bool, bool]:
    """Return (diff_text, install_script_added, install_script_changed,
    new_dependency_count, network_calls_in_lib, binary_data_added,
    git_url_dependency_added, obfuscated_code, persistence_mechanism_added,
    worm_propagation_pattern)."""
    old_keys = set(old_map)
    new_keys = set(new_map)

    new_files = sorted(new_keys - old_keys)
    changed = sorted(old_keys & new_keys)

    dangerous_new: list[str] = []
    dangerous_changed: list[str] = []
    regular_new_files: list[str] = []
    suspicious_binary: list[str] = []
    install_script_added = False
    install_script_changed = False
    new_dependency_count = 0
    network_calls_in_lib = False
    binary_data_added = False
    git_url_dependency_added = False
    obfuscated_code = False
    persistence_mechanism_added = False
    worm_propagation_pattern = False

    for rel in new_files:
        p = Path(rel)
        name = p.name
        suffix = p.suffix.lower()
        if name in INSTALL_HOOK_NAMES or rel in INSTALL_HOOK_NAMES:
            install_script_added = True
        # .pth files with import statements execute code at Python startup (persistence)
        if suffix == ".pth" and _pth_has_executable_code(new_map[rel]):
            install_script_added = True
        # AI editor config / secrets files in a package archive are red flags
        if name in _SUSPICIOUS_PACKAGE_FILES or any(
            rel.startswith(prefix) for prefix in _SUSPICIOUS_PACKAGE_PREFIXES
        ):
            regular_new_files.append(
                f"+ {rel} [SUSPICIOUS: should not appear in a package archive]"
            )
        # Zero-width Unicode steganography extended to all text source files (TrapDoor attack)
        if (
            name in {"CLAUDE.md", ".cursorrules"} or suffix in _ZERO_WIDTH_SOURCE_EXTENSIONS
        ) and _has_zero_width_unicode(new_map[rel]):
            obfuscated_code = True
        if suffix in DANGEROUS_BINARY_SUFFIXES:
            dangerous_new.append(rel)
        else:
            # Check for binary content in non-binary-extension files (gemstuffer pattern)
            if suffix not in _EXPECTED_BINARY_EXTENSIONS and _has_binary_content(new_map[rel]):
                binary_data_added = True
                suspicious_binary.append(rel)
            else:
                regular_new_files.append(f"+ {rel}")
            # Check for outbound network calls in library code (not install hooks)
            if (
                suffix in _NET_CALL_PATTERNS
                and name not in INSTALL_HOOK_NAMES
                and rel not in INSTALL_HOOK_NAMES
            ):
                new_text = _read_text(new_map[rel])
                if _added_lines_have_net_calls(new_text.splitlines(), suffix):
                    network_calls_in_lib = True
            # Check for obfuscation in new files
            if not obfuscated_code and suffix in _OBFUSCATION_PATTERNS:
                if _has_obfuscation(new_map[rel], suffix):
                    obfuscated_code = True
            # Dual gzip+base64 encoding — layered evasion of text-based scanners
            if not obfuscated_code and suffix in GZIP_B64_EXTENSIONS:
                if _has_gzip_b64_payload(new_map[rel]):
                    obfuscated_code = True
            # Check install hooks for persistence mechanisms (LaunchAgent, pm2, systemd, etc.)
            if not persistence_mechanism_added and (
                name in INSTALL_HOOK_NAMES or rel in INSTALL_HOOK_NAMES
            ):
                if _has_persistence_mechanism(_read_text(new_map[rel])):
                    persistence_mechanism_added = True
            # Check new JS/PY files for npm worm self-propagation pattern
            if not worm_propagation_pattern and suffix in {".js", ".py", ".ts", ".cjs", ".mjs"}:
                text = _read_text(new_map[rel])
                if _NPM_CRED_READ_RE.search(text) and _NPM_PUBLISH_RE.search(text):
                    worm_propagation_pattern = True

    high_signal_changed: list[tuple[str, str]] = []
    other_changed: list[str] = []

    for rel in changed:
        p = Path(rel)
        suffix = p.suffix.lower()
        if suffix in DANGEROUS_BINARY_SUFFIXES:
            old_hash = hashlib.sha256(old_map[rel].read_bytes()).hexdigest()
            new_hash = hashlib.sha256(new_map[rel].read_bytes()).hexdigest()
            if old_hash != new_hash:
                old_sz = old_map[rel].stat().st_size
                new_sz = new_map[rel].stat().st_size
                dangerous_changed.append(f"{rel} ({old_sz}→{new_sz} bytes)")
            continue

        old_text = _read_text(old_map[rel])
        new_text = _read_text(new_map[rel])
        if old_text == new_text:
            continue

        name = p.name
        if name in INSTALL_HOOK_NAMES or rel in INSTALL_HOOK_NAMES:
            install_script_changed = True
        elif name == "package.json" and _npm_install_scripts_added(old_map[rel], new_map[rel]):
            install_script_added = True

        if name == "package.json":
            new_dependency_count += _count_new_npm_deps(old_map[rel], new_map[rel])
            if not git_url_dependency_added and _npm_git_url_deps_added(old_map[rel], new_map[rel]):
                git_url_dependency_added = True
        elif name in _REQUIREMENTS_NAMES:
            new_dependency_count += _count_new_pip_deps(old_map[rel], new_map[rel])
            if not git_url_dependency_added and _pip_git_url_deps_added(old_map[rel], new_map[rel]):
                git_url_dependency_added = True
        elif name == "pyproject.toml":
            if not git_url_dependency_added and _pip_git_url_deps_added(old_map[rel], new_map[rel]):
                git_url_dependency_added = True
        elif name == "Cargo.toml":
            if not git_url_dependency_added and _cargo_git_deps_added(old_map[rel], new_map[rel]):
                git_url_dependency_added = True
        elif name == "composer.json":
            if _composer_autoload_files_added(old_map[rel], new_map[rel]):
                install_script_added = True
            elif _composer_plugin_type_added(old_map[rel], new_map[rel]):
                install_script_added = True
            elif _composer_plugin_api_added(old_map[rel], new_map[rel]):
                install_script_added = True
        elif suffix == ".pth":
            # Existing .pth that gains import lines — possible persistence injection
            added_pth = _diff_added_lines(old_text, new_text)
            if any(ln.strip().startswith(("import ", "import\t")) for ln in added_pth):
                install_script_changed = True
        elif name == "go.sum":
            # Removed checksum entries weaken module verification (Go tampering attack)
            if _go_sum_lines_removed(old_map[rel], new_map[rel]):
                install_script_changed = True

        # Check for newly-added outbound network calls in non-install-hook library code
        if (
            suffix in _NET_CALL_PATTERNS
            and name not in INSTALL_HOOK_NAMES
            and rel not in INSTALL_HOOK_NAMES
        ):
            added = _diff_added_lines(old_text, new_text)
            if _added_lines_have_net_calls(added, suffix):
                network_calls_in_lib = True

        # Check changed install hooks for persistence mechanisms
        if not persistence_mechanism_added and (
            name in INSTALL_HOOK_NAMES or rel in INSTALL_HOOK_NAMES
        ):
            if _has_persistence_mechanism(new_text):
                persistence_mechanism_added = True
        # Check changed files for npm worm propagation pattern
        if not worm_propagation_pattern and suffix in {".js", ".py", ".ts", ".cjs", ".mjs"}:
            if _NPM_CRED_READ_RE.search(new_text) and _NPM_PUBLISH_RE.search(new_text):
                worm_propagation_pattern = True

        if name in HIGH_RISK_NAMES or p.suffix in HIGH_RISK_SUFFIXES:
            patch = _unified_diff(old_text, new_text, rel)
            high_signal_changed.append((rel, patch))
        else:
            other_changed.append(rel)

    sections: list[str] = []

    if dangerous_new or dangerous_changed:
        lines: list[str] = []
        for rel in dangerous_new:
            lines.append(f"NEW: {rel}")
        for entry in dangerous_changed:
            lines.append(f"MODIFIED: {entry}")
        sections.append(
            "=== DANGEROUS BINARY/EXECUTABLE FILES ===\n"
            "(compiled extensions and pickle files execute code on load — automatic RED signal)\n"
            + "\n".join(lines)
        )

    if suspicious_binary:
        sections.append(
            "=== SUSPICIOUS: BINARY DATA IN NON-BINARY FILES ===\n"
            "(non-binary-extension files containing binary/non-text content — possible embedded payload or exfiltrated data)\n"
            + "\n".join(f"NEW: {rel}" for rel in suspicious_binary)
        )

    if regular_new_files:
        sections.append("=== NEW FILES ===\n" + "\n".join(regular_new_files))

    if high_signal_changed:
        parts = []
        for rel, patch in high_signal_changed:
            parts.append(patch)
        sections.append("=== CHANGED (high-signal) ===\n" + "\n".join(parts))

    if other_changed:
        sections.append("=== CHANGED (other) ===\n" + ", ".join(other_changed))

    if not sections:
        return (
            "[no significant changes detected]",
            install_script_added,
            install_script_changed,
            new_dependency_count,
            network_calls_in_lib,
            binary_data_added,
            git_url_dependency_added,
            obfuscated_code,
            persistence_mechanism_added,
            worm_propagation_pattern,
        )

    result = "\n\n".join(sections)

    total_bytes = len(result.encode())
    if total_bytes > MAX_DIFF_BYTES:
        truncated = result.encode()[:MAX_DIFF_BYTES].decode(errors="replace")
        result = truncated + f"\n[diff truncated at 100KB — {total_bytes} bytes total]"

    return (
        result,
        install_script_added,
        install_script_changed,
        new_dependency_count,
        network_calls_in_lib,
        binary_data_added,
        git_url_dependency_added,
        obfuscated_code,
        persistence_mechanism_added,
        worm_propagation_pattern,
    )


def _has_binary_content(path: Path, sample_size: int = 8192) -> bool:
    """Return True if a file contains binary (non-text) data.

    Null bytes are unambiguous. A high ratio of bytes outside printable ASCII
    plus common whitespace strongly indicates binary or compressed content.
    """
    try:
        sample = path.read_bytes()[:sample_size]
    except Exception:  # noqa: BLE001
        return False
    if not sample:
        return False
    if b"\x00" in sample:
        return True
    non_text = sum(1 for b in sample if b < 9 or (13 < b < 32) or b > 126)
    return (non_text / len(sample)) > 0.10


def _diff_added_lines(old_text: str, new_text: str) -> list[str]:
    """Extract lines added in new_text relative to old_text via unified diff."""
    result: list[str] = []
    for line in difflib.unified_diff(old_text.splitlines(), new_text.splitlines(), n=0):
        if line.startswith("+") and not line.startswith("+++"):
            result.append(line[1:])
    return result


def _added_lines_have_net_calls(lines: list[str], ext: str) -> bool:
    """Return True if any non-comment line matches a known network-call pattern for ext."""
    patterns = _NET_CALL_PATTERNS.get(ext, [])
    if not patterns:
        return False
    for line in lines:
        stripped = line.strip()
        # Skip single-line comments (rough heuristic — avoids false positives in docs)
        if stripped.startswith(("#", "//", "*", "--", "=begin", "/*")):
            continue
        for pattern in patterns:
            if pattern.search(line):
                return True
    return False


def _npm_install_scripts_added(old_path: Path, new_path: Path) -> bool:
    """Return True if new install-lifecycle script keys appear in package.json scripts field."""
    try:
        old_scripts = set(
            json.loads(old_path.read_text(errors="replace")).get("scripts", {}).keys()
        )
        new_scripts = set(
            json.loads(new_path.read_text(errors="replace")).get("scripts", {}).keys()
        )
        return bool((new_scripts - old_scripts) & NPM_INSTALL_SCRIPTS)
    except Exception:  # noqa: BLE001
        return False


def _count_new_npm_deps(old_path: Path, new_path: Path) -> int:
    """Return net new dependency keys added to package.json dependencies + devDependencies."""
    try:
        old_data = json.loads(old_path.read_text(errors="replace"))
        new_data = json.loads(new_path.read_text(errors="replace"))
        old_deps: set[str] = set(old_data.get("dependencies", {})) | set(
            old_data.get("devDependencies", {})
        )
        new_deps: set[str] = set(new_data.get("dependencies", {})) | set(
            new_data.get("devDependencies", {})
        )
        return len(new_deps - old_deps)
    except Exception:  # noqa: BLE001
        return 0


_REQUIREMENT_RE = __import__("re").compile(
    r"^\s*([A-Za-z0-9_.-][A-Za-z0-9_.\-\[\]]*)\s*[><=!@~;]?", __import__("re").ASCII
)


def _count_new_pip_deps(old_path: Path, new_path: Path) -> int:
    """Return net new dependency lines added to requirements.txt-style files."""

    def _parse_reqs(text: str) -> set[str]:
        names: set[str] = set()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            m = _REQUIREMENT_RE.match(line)
            if m:
                names.add(m.group(1).lower())
        return names

    try:
        old_names = _parse_reqs(old_path.read_text(errors="replace"))
        new_names = _parse_reqs(new_path.read_text(errors="replace"))
        return len(new_names - old_names)
    except Exception:  # noqa: BLE001
        return 0


def _has_obfuscation(path: Path, suffix: str) -> bool:
    """Return True if the file contains strong obfuscation patterns.

    Checks for:
    - javascript-obfuscator _0x hex variable names
    - eval/atob decode-then-exec chains (Coruna, TanStack patterns)
    - exec(compile(...)) Python obfuscation
    - Any single line exceeding 100 KB (machine-generated, not hand-minified)
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return False
    for line in text.splitlines():
        if len(line) > _OBFUSCATION_LINE_THRESHOLD:
            return True
    for pattern in _OBFUSCATION_PATTERNS.get(suffix, []):
        if pattern.search(text):
            return True
    return False


def _npm_git_url_deps_added(old_path: Path, new_path: Path) -> bool:
    """Return True if new npm deps pointing to git/GitHub URLs appear in package.json.

    Catches the AntV/TanStack Mini Shai-Hulud pattern:
      "optionalDependencies": {"@antv/setup": "github:antvis/G2#<commit>"}
    These bypass the npm registry and its malware scanning.
    """
    try:
        old_data = json.loads(old_path.read_text(errors="replace"))
        new_data = json.loads(new_path.read_text(errors="replace"))
        old_deps: dict[str, str] = {}
        new_deps: dict[str, str] = {}
        for section in (
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
        ):
            old_deps.update(old_data.get(section, {}))
            new_deps.update(new_data.get(section, {}))
        for pkg, version in new_deps.items():
            if pkg in old_deps:
                continue
            if any(str(version).startswith(p) for p in _GIT_DEP_PREFIXES):
                return True
            if _HTTP_DEP_RE.match(str(version)):
                return True
        return False
    except Exception:  # noqa: BLE001
        return False


def _npm_lockfile_integrity_downgraded(old_path: Path, new_path: Path) -> bool:
    """Return True if package-lock.json lost sha512 integrity entries or downgraded to sha1.

    PackageGate (Jan 2026): stripping sha512 entries from package-lock.json — or
    replacing them with sha1 entries exploitable via collision — bypasses npm's
    integrity verification. Legitimate version bumps never shrink the integrity map.
    """

    def _integrity_map(data: dict) -> dict[str, str]:
        result: dict[str, str] = {}
        for pkg_path, pkg_info in (data.get("packages") or {}).items():
            if isinstance(pkg_info, dict) and "integrity" in pkg_info:
                result[pkg_path] = pkg_info["integrity"]
        return result

    try:
        old_data = json.loads(old_path.read_text(errors="replace"))
        new_data = json.loads(new_path.read_text(errors="replace"))
    except Exception:  # noqa: BLE001
        return False

    old_integrity = _integrity_map(old_data)
    new_integrity = _integrity_map(new_data)

    for pkg_path, old_hash in old_integrity.items():
        if not old_hash.startswith("sha512-"):
            continue
        if pkg_path not in new_integrity:
            return True  # sha512 entry removed entirely
        if new_integrity[pkg_path].startswith("sha1-"):
            return True  # downgraded sha512 → sha1

    return False


def _composer_autoload_files_added(old_path: Path, new_path: Path) -> bool:
    """Return True if new files appear in composer.json autoload.files or autoload-dev.files.

    The autoload.files key executes PHP files on every require 'vendor/autoload.php' call,
    making it a reliable execution hook (Laravel Lang compromise pattern).
    """
    try:
        old_data = json.loads(old_path.read_text(errors="replace"))
        new_data = json.loads(new_path.read_text(errors="replace"))
        for key in ("autoload", "autoload-dev"):
            old_files = set(old_data.get(key, {}).get("files", []))
            new_files = set(new_data.get(key, {}).get("files", []))
            if new_files - old_files:
                return True
        return False
    except Exception:  # noqa: BLE001
        return False


def _pth_has_executable_code(path: Path) -> bool:
    """Return True if a .pth file contains executable Python (import statements).

    Legitimate .pth files contain only filesystem path entries (one per line).
    A line starting with 'import' executes at Python startup for every interpreter
    invocation — attackers use this as a persistence mechanism (CanisterWorm pattern).
    """
    try:
        for line in path.read_text(errors="replace").splitlines():
            stripped = line.strip()
            if stripped.startswith(("import ", "import\t")):
                return True
        return False
    except Exception:  # noqa: BLE001
        return False


def _composer_plugin_type_added(old_path: Path, new_path: Path) -> bool:
    """Return True if composer.json changed its type to 'composer-plugin'.

    Composer plugins register post-install-cmd/post-update-cmd hooks that run
    arbitrary code on every 'composer install'. A type change to 'composer-plugin'
    in a version bump is almost always malicious (Mini Shai-Hulud Packagist pattern).
    """
    try:
        old_type = json.loads(old_path.read_text(errors="replace")).get("type", "")
        new_type = json.loads(new_path.read_text(errors="replace")).get("type", "")
        return new_type == "composer-plugin" and old_type != "composer-plugin"
    except Exception:  # noqa: BLE001
        return False


def _composer_plugin_api_added(old_path: Path, new_path: Path) -> bool:
    """Return True if a new dependency on composer-plugin-api appears in composer.json.

    A package that requires composer-plugin-api gains the ability to register hooks
    (post-install-cmd, post-update-cmd) even when its 'type' field is not 'composer-plugin'.
    Adding this dependency mid-lifecycle to an existing package is a strong red flag
    (seen in Packagist supply chain campaigns, May 2026).
    """
    try:
        old_req = json.loads(old_path.read_text(errors="replace")).get("require", {})
        new_req = json.loads(new_path.read_text(errors="replace")).get("require", {})
        return "composer-plugin-api" in new_req and "composer-plugin-api" not in old_req
    except Exception:  # noqa: BLE001
        return False


def _pip_git_url_deps_added(old_path: Path, new_path: Path) -> bool:
    """Return True if new git-URL dep specs appear in requirements.txt or pyproject.toml.

    Catches git+https:// VCS URLs and PEP 508 `pkg @ https://...git` URL requirements
    that install directly from a git repo rather than from PyPI.
    """

    def _find(text: str) -> set[str]:
        found: set[str] = set()
        for line in text.splitlines():
            s = line.strip()
            if s and not s.startswith("#") and _PIP_GIT_DEP_RE.search(s):
                found.add(s.lower())
        return found

    try:
        return bool(
            _find(new_path.read_text(errors="replace"))
            - _find(old_path.read_text(errors="replace"))
        )
    except Exception:  # noqa: BLE001
        return False


def _cargo_git_deps_added(old_path: Path, new_path: Path) -> bool:
    """Return True if new git-sourced deps appear in Cargo.toml.

    Catches: some-crate = { git = "https://github.com/..." }
    These bypass crates.io and its malware scanning.
    """

    def _find(text: str) -> set[str]:
        found: set[str] = set()
        for line in text.splitlines():
            s = line.strip()
            if s and not s.startswith("#") and _CARGO_GIT_DEP_RE.search(s):
                found.add(s.lower())
        return found

    try:
        return bool(
            _find(new_path.read_text(errors="replace"))
            - _find(old_path.read_text(errors="replace"))
        )
    except Exception:  # noqa: BLE001
        return False


def _go_sum_lines_removed(old_path: Path, new_path: Path) -> bool:
    """Return True if go.sum has fewer hash entries in the new version.

    Legitimate updates only add new entries to go.sum. Removing existing entries
    disables checksum verification for those modules — a supply chain tampering
    technique used to substitute malicious versions without detection.
    """

    def _entries(path: Path) -> set[str]:
        found: set[str] = set()
        for line in path.read_text(errors="replace").splitlines():
            s = line.strip()
            if s and not s.startswith("#"):
                found.add(s)
        return found

    try:
        return bool(_entries(old_path) - _entries(new_path))
    except Exception:  # noqa: BLE001
        return False


def _has_zero_width_unicode(path: Path) -> bool:
    """Return True if the file contains zero-width Unicode characters.

    These invisible code points (U+200B/200C/200D, U+2060, U+FEFF, U+FFFC) have no
    legitimate use in package source files. Attackers embed them in AI editor config
    files (.cursorrules, CLAUDE.md) to inject hidden instructions that the AI executes
    while appearing as a blank line to human reviewers (TrapDoor attack, May 2026).
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        return bool(_ZERO_WIDTH_RE.search(text))
    except Exception:  # noqa: BLE001
        return False


def _has_gzip_b64_payload(path: Path) -> bool:
    """Return True if the file contains a base64-encoded gzip payload.

    Gzip data in base64 always starts with 'H4sI' (the bytes \x1f\x8b\x08 encoded).
    Attackers layer gzip+base64 to make payloads look like random noise while evading
    text-based scanners (seen in npm/pip campaigns, Socket blog May 2026).
    Requires ≥60 additional base64 chars after the magic to avoid false positives.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        return bool(_GZIP_B64_RE.search(text))
    except Exception:  # noqa: BLE001
        return False


def _has_persistence_mechanism(text: str) -> bool:
    """Return True if the text contains known OS-level persistence installation patterns.

    Checks for: macOS LaunchAgent drops, systemd user service registration, pm2 daemon
    setup, Bun runtime bootstrap, home-directory wipe trigger, and secrets-scanner weaponisation.
    Any match in a lifecycle script (install/preinstall/postinstall/setup.py) is a strong RED signal.
    """
    return any(p.search(text) for p in _PERSISTENCE_PATTERNS)


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return ""


def _unified_diff(old_text: str, new_text: str, filename: str) -> str:
    old_lines = old_text.splitlines(keepends=True)
    new_lines = new_text.splitlines(keepends=True)
    diff = difflib.unified_diff(
        old_lines,
        new_lines,
        fromfile=f"{filename} (old)",
        tofile=f"{filename} (new)",
    )
    return "".join(diff)


def _count_extra_lines(source: str, archive: str) -> list[str]:
    """Return lines present in archive but not in source, excluding version-string changes."""
    extra = []
    for line in difflib.unified_diff(source.splitlines(), archive.splitlines(), n=0):
        if line.startswith("+") and not line.startswith("+++"):
            actual = line[1:]
            if not _VERSION_LINE_RE.match(actual.strip()):
                extra.append(actual)
    return extra


async def _get_vcs_repo_for_package(
    client: httpx.AsyncClient, ecosystem: str, package: str, version: str
) -> tuple[str, str] | None:
    """Return (platform, 'owner/repo') by querying the package registry, or None."""
    try:
        if ecosystem == "pip":
            resp = await client.get(f"https://pypi.org/pypi/{package}/{version}/json", timeout=10.0)
            if resp.status_code != 200:
                return None
            info = resp.json().get("info", {})
            project_urls = info.get("project_urls") or {}
            source_url = (
                project_urls.get("Source Code")
                or project_urls.get("Source")
                or project_urls.get("Repository")
                or info.get("home_page")
                or ""
            )
            return parse_vcs_repo(source_url)
        elif ecosystem == "npm":
            resp = await client.get(f"https://registry.npmjs.org/{package}/{version}", timeout=10.0)
            if resp.status_code != 200:
                return None
            repo_field = resp.json().get("repository") or {}
            url = repo_field.get("url", "") if isinstance(repo_field, dict) else str(repo_field)
            return parse_vcs_repo(url)
    except Exception:  # noqa: BLE001
        pass
    return None


async def _compare_artifact_to_source(
    client: httpx.AsyncClient,
    ecosystem: str,
    package: str,
    new_version: str,
    artifact_files: dict[str, str],
) -> tuple[bool, list[str]]:
    """Return (mismatch_found, [paths with unexplained extra lines vs git tag source]).

    Detects XZ-style attacks: code injected into the published archive that is absent
    from the corresponding git tag, indicating the release was tampered after tagging.
    """
    if not artifact_files:
        return False, []

    vcs = await _get_vcs_repo_for_package(client, ecosystem, package, new_version)
    if vcs is None:
        return False, []

    platform, owner_repo = vcs
    owner, repo = owner_repo.split("/", 1)
    token = os.environ.get("GITHUB_TOKEN")

    paths = list(artifact_files.keys())
    filenames = [Path(p).name for p in paths]

    source_contents = await asyncio.gather(
        *[
            fetch_vcs_file_at_tag(platform, owner, repo, new_version, fname, token)
            for fname in filenames
        ],
        return_exceptions=True,
    )

    mismatch_files: list[str] = []
    for rel_path, source_content in zip(paths, source_contents):
        if not isinstance(source_content, str):
            continue
        archive_content = artifact_files[rel_path]
        extra = _count_extra_lines(source_content, archive_content)
        if len(extra) >= _ARTIFACT_MISMATCH_THRESHOLD:
            mismatch_files.append(rel_path)

    return bool(mismatch_files), mismatch_files
