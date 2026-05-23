"""
Activity: compute a security-focused diff between two PyPI package versions.
Downloads both sdists, extracts them, and returns a DiffSignals model.
"""
from __future__ import annotations

import asyncio
import base64
import difflib
import hashlib
import hmac
import io
import stat
import tarfile
import tempfile
import urllib.parse
import zipfile
from pathlib import Path

import httpx
from temporalio import activity
from temporalio.exceptions import ApplicationError

from activities.models import DiffSignals

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_DOWNLOAD_BYTES = 20 * 1024 * 1024  # 20 MB
MAX_EXTRACT_BYTES = 100 * 1024 * 1024  # 100 MB — zip bomb guard
MAX_DIFF_BYTES = 100 * 1024  # 100 KB

# Allowlist of CDN hosts from which we will download package archives.
# Any URL whose host is not in this set is rejected before the HTTP request
# is made, preventing SSRF attacks via attacker-controlled registry metadata.
_ALLOWED_CDN_HOSTS: frozenset[str] = frozenset({
    "files.pythonhosted.org",  # PyPI sdists + wheels
    "registry.npmjs.org",       # npm tarballs
})

NOISE_DIRS = {".dist-info", "__pycache__", ".egg-info", "node_modules", ".nyc_output", "coverage"}
NOISE_SUFFIXES = {".pyc", ".pyo"}
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
}
HIGH_SIGNAL_SUFFIXES = {".pth"}  # Python path config files — silent code-exec vector

# Files that execute code on load / are impossible to text-diff safely.
# A new or modified file with any of these extensions is an automatic RED signal.
DANGEROUS_BINARY_SUFFIXES = {
    ".so", ".pyd", ".dll",       # native compiled extensions — execute arbitrary code
    ".node",                     # Node.js native add-ons — execute arbitrary native code
    ".pkl", ".pickle",            # deserializes and executes arbitrary Python objects
}


# ---------------------------------------------------------------------------
# Activity entry point
# ---------------------------------------------------------------------------

@activity.defn(name="activities.package_diff.compute")
async def compute(ecosystem: str, package: str, old_version: str, new_version: str) -> DiffSignals:
    activity.logger.info(
        f"Computing package diff for {package} {old_version} -> {new_version}"
    )

    _url_fetcher = _get_npm_tarball_url if ecosystem == "npm" else _get_sdist_url

    async with httpx.AsyncClient(timeout=30.0) as client:
        old_info, new_info = await asyncio.gather(
            _url_fetcher(client, package, old_version),
            _url_fetcher(client, package, new_version),
        )

        if old_info is None or new_info is None:
            return DiffSignals(diff_summary="[sdist not available]", diff_size_bytes=0)

        old_url, old_filename, old_sha256 = old_info
        new_url, new_filename, new_sha256 = new_info

        old_bytes, new_bytes = await asyncio.gather(
            _download(client, old_url, old_sha256),
            _download(client, new_url, new_sha256),
        )

    if old_bytes is None or new_bytes is None:
        return DiffSignals(
            diff_summary="[download aborted: archive exceeds 20 MB size limit]",
            diff_size_bytes=0,
        )

    # Extraction and diff are CPU/blocking I/O — run in a thread.
    diff_summary = await asyncio.to_thread(
        _extract_and_diff, old_bytes, old_filename, new_bytes, new_filename
    )

    return DiffSignals(
        diff_summary=diff_summary,
        diff_size_bytes=len(diff_summary.encode()),
    )


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

async def _get_sdist_url(
    client: httpx.AsyncClient, package: str, version: str
) -> tuple[str, str, str] | None:
    """Return (url, filename, sha256) for the best available archive, or None."""
    url = f"https://pypi.org/pypi/{package}/{version}/json"
    resp = await client.get(url)
    if resp.status_code == 404:
        raise ApplicationError(
            f"{package}=={version} not found on PyPI",
            type="PackageNotFound",
            non_retryable=True,
        )
    resp.raise_for_status()
    data = resp.json()
    urls: list[dict] = data.get("urls", [])

    # Prefer sdist, fall back to wheel
    for pkg_type in ("sdist", "bdist_wheel"):
        for entry in urls:
            if entry.get("packagetype") == pkg_type:
                archive_url = entry["url"]
                _validate_archive_url(archive_url)
                return archive_url, entry["filename"], entry.get("digests", {}).get("sha256", "")

    return None


async def _get_npm_tarball_url(
    client: httpx.AsyncClient, package: str, version: str
) -> tuple[str, str, str] | None:
    """Return (url, filename, integrity) for an npm package tarball, or None.

    integrity is the dist.integrity SRI string (e.g. 'sha512-...') used by
    _download for tamper detection. We prefer SHA512 over the legacy SHA1 shasum.
    """
    resp = await client.get(f"https://registry.npmjs.org/{package}/{version}")
    if resp.status_code == 404:
        raise ApplicationError(
            f"{package}@{version} not found on npm registry",
            type="PackageNotFound",
            non_retryable=True,
        )
    resp.raise_for_status()
    data = resp.json()
    dist = data.get("dist") or {}
    tarball_url = dist.get("tarball", "")
    if not tarball_url:
        return None
    _validate_archive_url(tarball_url)
    return tarball_url, tarball_url.split("/")[-1], dist.get("integrity", "")


def _validate_archive_url(url: str) -> None:
    """Reject any archive URL that doesn't come from a trusted CDN host.

    Without this check an attacker who controls registry metadata (via a MITM
    or a compromised upstream registry) could redirect our download to an
    internal service (169.254.169.254, localhost, internal APIs).
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        raise ApplicationError(
            f"Insecure archive URL scheme '{parsed.scheme}' — only https is allowed",
            non_retryable=True,
        )
    if parsed.netloc not in _ALLOWED_CDN_HOSTS:
        raise ApplicationError(
            f"Untrusted archive host '{parsed.netloc}' — "
            f"expected one of {sorted(_ALLOWED_CDN_HOSTS)}",
            non_retryable=True,
        )


async def _download(client: httpx.AsyncClient, url: str, integrity: str) -> bytes | None:
    """Download *url*, verify integrity, return bytes or None if oversized.

    integrity formats accepted:
      - 64-char hex string        → SHA-256 (PyPI digests.sha256)
      - 'sha512-<base64>'         → SHA-512 SRI (npm dist.integrity)
      - ''                        → no verification (not recommended)
    """
    _validate_archive_url(url)

    chunks: list[bytes] = []
    total = 0
    async with client.stream("GET", url) as resp:
        resp.raise_for_status()
        async for chunk in resp.aiter_bytes(chunk_size=65536):
            total += len(chunk)
            if total > MAX_DOWNLOAD_BYTES:
                return None
            chunks.append(chunk)
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
        # Plain SHA-256 hex digest (PyPI)
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
) -> str:
    try:
        with tempfile.TemporaryDirectory() as old_dir, tempfile.TemporaryDirectory() as new_dir:
            _extract_to_dir(old_bytes, old_filename, old_dir)
            _extract_to_dir(new_bytes, new_filename, new_dir)
            old_map = _get_file_map(old_dir)
            new_map = _get_file_map(new_dir)
            return _build_diff(old_map, new_map)
    except Exception as exc:  # noqa: BLE001
        return f"[extraction error: {exc}]"


def _extract_to_dir(archive_bytes: bytes, filename: str, dest: str) -> None:
    """Extract *archive_bytes* (named *filename*) into *dest*."""
    buf = io.BytesIO(archive_bytes)
    dest_path = Path(dest).resolve()
    lower = filename.lower()
    if lower.endswith((".tar.gz", ".tar.bz2", ".tgz")):
        with tarfile.open(fileobj=buf) as tf:
            tf.extractall(dest, filter="data")  # filter="data" blocks path traversal
    elif lower.endswith((".whl", ".zip")):
        with zipfile.ZipFile(buf) as zf:
            _safe_zip_extractall(zf, dest_path)
    else:
        raise ValueError(f"Unsupported archive format: {filename}")


def _safe_zip_extractall(zf: zipfile.ZipFile, dest: Path) -> None:
    """Extract a zip file with path traversal, symlink, and zip-bomb protection."""
    total_extracted = 0
    for member in zf.infolist():
        # Reject symlink entries. Zip symlinks have Unix mode 0o120xxx on the
        # external_attr field. A symlink pointing outside the destination could
        # be used to read arbitrary files (e.g. ~/.ssh/id_rsa) even though the
        # filename itself passes the path-traversal check below.
        unix_mode = (member.external_attr >> 16) & 0xFFFF
        if stat.S_ISLNK(unix_mode):
            raise ApplicationError(
                f"Zip contains symlink entry: {member.filename}",
                non_retryable=True,
            )
        # Normalize and check for path traversal
        member_path = (dest / member.filename).resolve()
        if not str(member_path).startswith(str(dest)):
            raise ApplicationError(
                f"Zip path traversal attempt: {member.filename}",
                non_retryable=True,
            )
        # Guard against zip bombs
        total_extracted += member.file_size
        if total_extracted > MAX_EXTRACT_BYTES:
            raise ApplicationError(
                "Zip extraction size limit exceeded (possible zip bomb)",
                non_retryable=True,
            )
        zf.extract(member, dest)


def _is_noise(rel: str) -> bool:
    """Return True if this path should be excluded from the diff."""
    parts = Path(rel).parts
    # Check directory components for noise patterns
    for part in parts[:-1]:
        if part in NOISE_DIRS:
            return True
        if part.endswith(".egg-info") or part.endswith(".dist-info"):
            return True
    # Check filename
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
    # Detect top-level directory to strip (sdist convention)
    top_level_dirs = {p.relative_to(base).parts[0] for p in all_files if p.relative_to(base).parts}
    strip_top = len(top_level_dirs) == 1  # single top-level dir → strip it

    for path in all_files:
        if not path.is_file():
            continue
        rel = path.relative_to(base)
        parts = rel.parts
        if strip_top and len(parts) > 1:
            rel_str = str(Path(*parts[1:]))
        elif strip_top and len(parts) == 1:
            # File directly in the top-level dir — skip (rare)
            continue
        else:
            rel_str = str(rel)

        if _is_noise(rel_str):
            continue
        result[rel_str] = path

    return result


def _build_diff(old_map: dict[str, Path], new_map: dict[str, Path]) -> str:
    old_keys = set(old_map)
    new_keys = set(new_map)

    new_files = sorted(new_keys - old_keys)
    changed = sorted(old_keys & new_keys)

    # Dangerous binary files — new or modified — separated before any text analysis.
    dangerous_new: list[str] = []
    dangerous_changed: list[str] = []
    regular_new_files: list[str] = []

    for rel in new_files:
        if Path(rel).suffix.lower() in DANGEROUS_BINARY_SUFFIXES:
            dangerous_new.append(rel)
        else:
            regular_new_files.append(f"+ {rel}")

    high_signal_changed: list[tuple[str, str]] = []
    other_changed: list[str] = []

    for rel in changed:
        suffix = Path(rel).suffix.lower()
        if suffix in DANGEROUS_BINARY_SUFFIXES:
            # Can't text-diff — compare by SHA256 to detect modification
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
        name = Path(rel).name
        if name in HIGH_SIGNAL_NAMES or Path(name).suffix in HIGH_SIGNAL_SUFFIXES:
            patch = _unified_diff(old_text, new_text, rel)
            high_signal_changed.append((rel, patch))
        else:
            other_changed.append(rel)

    sections: list[str] = []

    # Dangerous binary section always appears first — makes it impossible to miss.
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
        return "[no significant changes detected]"

    result = "\n\n".join(sections)

    total_bytes = len(result.encode())
    if total_bytes > MAX_DIFF_BYTES:
        truncated = result.encode()[:MAX_DIFF_BYTES].decode(errors="replace")
        result = truncated + f"\n[diff truncated at 100KB — {total_bytes} bytes total]"

    return result


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
