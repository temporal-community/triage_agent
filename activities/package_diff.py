"""
Activity: compute a security-focused diff between two package versions.
Downloads both archives, extracts them, and returns a DiffSignals model.
Archive format and CDN host are fully delegated to the ecosystem provider.
"""
from __future__ import annotations

import asyncio
import base64
import difflib
import hashlib
import hmac
import json
import re
import tempfile
from collections.abc import Callable
from pathlib import Path

import httpx
from temporalio import activity
from temporalio.exceptions import ApplicationError

from activities.ecosystems import get_provider, validate_archive_url
from activities.models import DiffSignals

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_DOWNLOAD_BYTES = 20 * 1024 * 1024  # 20 MB
MAX_DIFF_BYTES = 100 * 1024  # 100 KB

NOISE_DIRS = {".dist-info", "__pycache__", ".egg-info", "node_modules", ".nyc_output", "coverage", "META-INF"}
NOISE_SUFFIXES = {".pyc", ".pyo", ".rbc"}  # .rbc = Ruby bytecode cache
NOISE_FILENAMES = {"RECORD", "WHEEL", "METADATA", "INSTALLER", "package-lock.json", "yarn.lock", "npm-shrinkwrap.json"}

HIGH_SIGNAL_NAMES = {
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
    "pom.xml",
    "composer.json",
}
HIGH_SIGNAL_SUFFIXES = {".pth", ".gemspec"}

# Subset of HIGH_SIGNAL_NAMES that execute code on install — changes are an explicit red/yellow flag.
INSTALL_HOOK_NAMES = {
    "setup.py",       # pip: customises build/install steps
    "install.js",     # npm: install lifecycle script
    "postinstall.js", # npm: postinstall hook
    "preinstall.js",  # npm: preinstall hook
    "extconf.rb",     # rubygems: C-extension build script
}
# Keys in package.json scripts{} that run during install.
NPM_INSTALL_SCRIPTS = {"install", "preinstall", "postinstall", "prepare"}

# Files that execute code on load / are impossible to text-diff safely.
# A new or modified file with any of these extensions is an automatic RED signal.
DANGEROUS_BINARY_SUFFIXES = {
    ".so", ".pyd", ".dll",       # native compiled extensions — execute arbitrary code
    ".node",                     # Node.js native add-ons — execute arbitrary native code
    ".pkl", ".pickle",            # deserializes and executes arbitrary Python objects
    ".bundle",                   # Ruby native C extensions (macOS .dylib-like)
}

# Extensions that are legitimately binary and don't need content inspection.
# Files with these extensions are skipped for the binary_data_added check.
_EXPECTED_BINARY_EXTENSIONS = DANGEROUS_BINARY_SUFFIXES | {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".bmp", ".tiff",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".zip", ".tar", ".gz", ".bz2", ".xz",
    ".pdf", ".db", ".sqlite", ".sqlite3",
    ".mp3", ".mp4", ".wav", ".avi", ".mov",
    ".exe", ".bin", ".dat",
}

# Per-extension regex patterns for outbound network calls.
# Matched against newly-added lines only (not pre-existing code) in non-install-hook files.
_NET_CALL_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    ext: [re.compile(p) for p in patterns]
    for ext, patterns in {
        ".rb": [
            r"Net::HTTP\b", r"URI\.open\b", r"open-uri",
            r"Faraday\b", r"HTTParty\b", r"RestClient\b",
            r"Excon\b", r"Typhoeus\b",
            r"\bHTTP\.(get|post|head|put|delete|patch)\b",
        ],
        ".py": [
            r"\brequests\.(get|post|put|delete|head|patch|request)\s*\(",
            r"\burllib\.request\b", r"\burlopen\s*\(",
            r"\bhttpx\.(get|post|put|delete|head|patch|request|AsyncClient|Client)\b",
            r"\baiohttp\.(ClientSession|request)\b",
            r"\bhttp\.client\.(HTTPConnection|HTTPSConnection)\b",
        ],
        ".js": [
            r"\bfetch\s*\(", r"\baxios\.(get|post|put|delete|request|create)\b",
            r"\bhttps?\.(request|get)\s*\(", r"\bXMLHttpRequest\b",
            r"\bgot\s*[\.(]", r"\bsuperagent\b", r"\bnode-fetch\b",
        ],
        ".ts": [
            r"\bfetch\s*\(", r"\baxios\.(get|post|put|delete|request|create)\b",
            r"\bhttps?\.(request|get)\s*\(", r"\bXMLHttpRequest\b",
        ],
        ".mjs": [
            r"\bfetch\s*\(", r"\baxios\b", r"\bhttps?\.(request|get)\s*\(",
        ],
        ".php": [
            r"\bcurl_exec\s*\(", r"\bcurl_init\s*\(",
            r"\bfile_get_contents\s*\(\s*['\"]https?://",
            r"\bGuzzleHttp\\", r"\\Http\\Client\b",
        ],
        ".java": [
            r"\bHttpClient\b", r"\bHttpURLConnection\b", r"\bOkHttpClient\b",
            r"\bRestTemplate\b", r"\bWebClient\b",
        ],
    }.items()
}


# ---------------------------------------------------------------------------
# Activity entry point
# ---------------------------------------------------------------------------

@activity.defn(name="activities.package_diff.compute")
async def compute(ecosystem: str, package: str, old_version: str, new_version: str) -> DiffSignals:
    activity.logger.info(
        f"Computing package diff for {package} {old_version} -> {new_version}"
    )

    provider = get_provider(ecosystem)

    async with httpx.AsyncClient(timeout=30.0) as client:
        old_info, new_info = await asyncio.gather(
            provider.get_archive_url(client, package, old_version),
            provider.get_archive_url(client, package, new_version),
        )

        if old_info is None or new_info is None:
            return DiffSignals(diff_summary="[sdist not available]", diff_size_bytes=0)

        old_url, old_filename, old_integrity = old_info
        new_url, new_filename, new_integrity = new_info

        activity.heartbeat("downloading archives")
        old_bytes, new_bytes = await asyncio.gather(
            _download(client, old_url, old_integrity, heartbeat=activity.heartbeat),
            _download(client, new_url, new_integrity, heartbeat=activity.heartbeat),
        )

    if old_bytes is None or new_bytes is None:
        return DiffSignals(
            diff_summary="[download aborted: archive exceeds 20 MB size limit]",
            diff_size_bytes=0,
        )

    # Extraction and diff are CPU/blocking I/O — run in a thread.
    activity.heartbeat("extracting and diffing")
    diff_summary, install_script_added, install_script_changed, new_dep_count, net_calls, binary_data = (
        await asyncio.to_thread(
            _extract_and_diff, old_bytes, old_filename, new_bytes, new_filename, provider
        )
    )

    return DiffSignals(
        diff_summary=diff_summary,
        diff_size_bytes=len(diff_summary.encode()),
        install_script_added=install_script_added,
        install_script_changed=install_script_changed,
        new_dependency_count=new_dep_count,
        network_calls_in_lib=net_calls,
        binary_data_added=binary_data,
    )


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
        expected_bytes = base64.b64decode(integrity[len("sha512-"):])
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
) -> tuple[str, bool, bool, int, bool, bool]:
    try:
        with tempfile.TemporaryDirectory() as old_dir, tempfile.TemporaryDirectory() as new_dir:
            provider.extract_archive(old_bytes, old_filename, old_dir)
            provider.extract_archive(new_bytes, new_filename, new_dir)
            old_map = _get_file_map(old_dir)
            new_map = _get_file_map(new_dir)
            return _build_diff(old_map, new_map)
    except Exception as exc:  # noqa: BLE001
        return f"[extraction error: {exc}]", False, False, 0, False, False


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
    if Path(name).suffix in HIGH_SIGNAL_SUFFIXES:
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


_REQUIREMENTS_NAMES = frozenset({
    "requirements.txt", "requirements-dev.txt", "requirements-test.txt",
    "requirements-prod.txt", "requirements-base.txt",
})


def _build_diff(
    old_map: dict[str, Path], new_map: dict[str, Path]
) -> tuple[str, bool, bool, int, bool, bool]:
    """Return (diff_text, install_script_added, install_script_changed,
               new_dependency_count, network_calls_in_lib, binary_data_added)."""
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

    for rel in new_files:
        p = Path(rel)
        name = p.name
        suffix = p.suffix.lower()
        if name in INSTALL_HOOK_NAMES:
            install_script_added = True
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
            if suffix in _NET_CALL_PATTERNS and name not in INSTALL_HOOK_NAMES:
                new_text = _read_text(new_map[rel])
                if _added_lines_have_net_calls(new_text.splitlines(), suffix):
                    network_calls_in_lib = True

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
        if name in INSTALL_HOOK_NAMES:
            install_script_changed = True
        elif name == "package.json" and _npm_install_scripts_added(old_map[rel], new_map[rel]):
            install_script_added = True

        if name == "package.json":
            new_dependency_count += _count_new_npm_deps(old_map[rel], new_map[rel])
        elif name in _REQUIREMENTS_NAMES:
            new_dependency_count += _count_new_pip_deps(old_map[rel], new_map[rel])

        # Check for newly-added outbound network calls in non-install-hook library code
        if suffix in _NET_CALL_PATTERNS and name not in INSTALL_HOOK_NAMES:
            added = _diff_added_lines(old_text, new_text)
            if _added_lines_have_net_calls(added, suffix):
                network_calls_in_lib = True

        if name in HIGH_SIGNAL_NAMES or p.suffix in HIGH_SIGNAL_SUFFIXES:
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
        return "[no significant changes detected]", install_script_added, install_script_changed, new_dependency_count, network_calls_in_lib, binary_data_added

    result = "\n\n".join(sections)

    total_bytes = len(result.encode())
    if total_bytes > MAX_DIFF_BYTES:
        truncated = result.encode()[:MAX_DIFF_BYTES].decode(errors="replace")
        result = truncated + f"\n[diff truncated at 100KB — {total_bytes} bytes total]"

    return result, install_script_added, install_script_changed, new_dependency_count, network_calls_in_lib, binary_data_added


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
        old_scripts = set(json.loads(old_path.read_text(errors="replace")).get("scripts", {}).keys())
        new_scripts = set(json.loads(new_path.read_text(errors="replace")).get("scripts", {}).keys())
        return bool((new_scripts - old_scripts) & NPM_INSTALL_SCRIPTS)
    except Exception:  # noqa: BLE001
        return False


def _count_new_npm_deps(old_path: Path, new_path: Path) -> int:
    """Return net new dependency keys added to package.json dependencies + devDependencies."""
    try:
        old_data = json.loads(old_path.read_text(errors="replace"))
        new_data = json.loads(new_path.read_text(errors="replace"))
        old_deps: set[str] = set(old_data.get("dependencies", {})) | set(old_data.get("devDependencies", {}))
        new_deps: set[str] = set(new_data.get("dependencies", {})) | set(new_data.get("devDependencies", {}))
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
