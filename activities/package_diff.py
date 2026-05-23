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
import tempfile
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

NOISE_DIRS = {".dist-info", "__pycache__", ".egg-info", "node_modules", ".nyc_output", "coverage"}
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
}
HIGH_SIGNAL_SUFFIXES = {".pth", ".gemspec"}

# Files that execute code on load / are impossible to text-diff safely.
# A new or modified file with any of these extensions is an automatic RED signal.
DANGEROUS_BINARY_SUFFIXES = {
    ".so", ".pyd", ".dll",       # native compiled extensions — execute arbitrary code
    ".node",                     # Node.js native add-ons — execute arbitrary native code
    ".pkl", ".pickle",            # deserializes and executes arbitrary Python objects
    ".bundle",                   # Ruby native C extensions (macOS .dylib-like)
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

        old_bytes, new_bytes = await asyncio.gather(
            _download(client, old_url, old_integrity),
            _download(client, new_url, new_integrity),
        )

    if old_bytes is None or new_bytes is None:
        return DiffSignals(
            diff_summary="[download aborted: archive exceeds 20 MB size limit]",
            diff_size_bytes=0,
        )

    # Extraction and diff are CPU/blocking I/O — run in a thread.
    diff_summary = await asyncio.to_thread(
        _extract_and_diff, old_bytes, old_filename, new_bytes, new_filename, provider
    )

    return DiffSignals(
        diff_summary=diff_summary,
        diff_size_bytes=len(diff_summary.encode()),
    )


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

async def _download(client: httpx.AsyncClient, url: str, integrity: str) -> bytes | None:
    """Download *url*, verify integrity, return bytes or None if oversized.

    integrity formats accepted:
      - 64-char hex string        → SHA-256 (PyPI digests.sha256)
      - 'sha512-<base64>'         → SHA-512 SRI (npm dist.integrity)
      - ''                        → no verification
    """
    validate_archive_url(url)

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
) -> str:
    try:
        with tempfile.TemporaryDirectory() as old_dir, tempfile.TemporaryDirectory() as new_dir:
            provider.extract_archive(old_bytes, old_filename, old_dir)
            provider.extract_archive(new_bytes, new_filename, new_dir)
            old_map = _get_file_map(old_dir)
            new_map = _get_file_map(new_dir)
            return _build_diff(old_map, new_map)
    except Exception as exc:  # noqa: BLE001
        return f"[extraction error: {exc}]"


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


def _build_diff(old_map: dict[str, Path], new_map: dict[str, Path]) -> str:
    old_keys = set(old_map)
    new_keys = set(new_map)

    new_files = sorted(new_keys - old_keys)
    changed = sorted(old_keys & new_keys)

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
