"""
Detection pattern loader.

Loads built-in YAML detection files, then discovers any installed
``dependency_scout.signatures`` (YAML directory) or
``dependency_scout.signature_providers`` (Python callable) plugins and merges
their patterns in before compiling and exporting the final constants.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_DIR = Path(__file__).parent
_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _load(path: Path) -> Any:
    with open(path) as f:
        return yaml.safe_load(f)


def _compile_by_ext(raw: dict) -> dict[str, list[re.Pattern[str]]]:
    return {
        ext: [re.compile(e["pattern"] if isinstance(e, dict) else e) for e in entries]
        for ext, entries in raw.items()
        if entries
    }


def _compile_list(raw: list) -> list[re.Pattern[str]]:
    return [re.compile(e["pattern"] if isinstance(e, dict) else e) for e in raw]


def _merge_yaml_dir(directory: Path, acc: dict) -> None:
    """Merge patterns from a third-party YAML directory into *acc*."""
    if (p := directory / "net_calls.yaml").exists():
        for ext, patterns in (yaml.safe_load(p.read_text()) or {}).items():
            if patterns:
                acc["net_calls"].setdefault(ext, [])
                acc["net_calls"][ext] = acc["net_calls"][ext] + list(patterns)

    if (p := directory / "obfuscation.yaml").exists():
        data = yaml.safe_load(p.read_text()) or {}
        for ext, patterns in (data.get("patterns") or {}).items():
            if patterns:
                acc["obfuscation"].setdefault(ext, [])
                acc["obfuscation"][ext] = acc["obfuscation"][ext] + list(patterns)

    if (p := directory / "persistence.yaml").exists():
        data = yaml.safe_load(p.read_text()) or {}
        acc["persistence"].extend(data.get("patterns") or [])

    if (p := directory / "file_types.yaml").exists():
        data = yaml.safe_load(p.read_text()) or {}
        acc["suspicious_files"].extend(data.get("suspicious_filenames") or [])
        acc["suspicious_prefixes"].extend(data.get("suspicious_path_prefixes") or [])
        acc["dangerous_binary"].extend(data.get("dangerous_binary_suffixes") or [])
        acc["install_hooks"].extend(data.get("install_hook_names") or [])
        acc["npm_install_scripts"].extend(data.get("npm_install_scripts") or [])


def _merge_contribution(contrib: SignatureContribution, acc: dict) -> None:
    """Merge a :class:`SignatureContribution` into *acc*."""
    for ext, patterns in contrib.net_call_patterns.items():
        acc["net_calls"].setdefault(ext, [])
        acc["net_calls"][ext] = acc["net_calls"][ext] + list(patterns)

    for ext, patterns in contrib.obfuscation_patterns.items():
        acc["obfuscation"].setdefault(ext, [])
        acc["obfuscation"][ext] = acc["obfuscation"][ext] + list(patterns)

    acc["persistence"].extend(contrib.persistence_patterns)
    acc["suspicious_files"].extend(contrib.suspicious_package_files)
    acc["suspicious_prefixes"].extend(contrib.suspicious_package_prefixes)
    acc["dangerous_binary"].extend(contrib.dangerous_binary_suffixes)
    acc["install_hooks"].extend(contrib.install_hook_names)
    acc["npm_install_scripts"].extend(contrib.npm_install_scripts)


# ---------------------------------------------------------------------------
# Public plugin API
# ---------------------------------------------------------------------------


@dataclass
class SignatureContribution:
    """
    Returned by ``dependency_scout.signature_providers`` entry points.

    All pattern strings are raw regex strings — they are compiled internally.
    Only populate the fields you are contributing; unset fields are ignored.

    Example::

        from checks.signatures import SignatureContribution

        def get_signatures() -> SignatureContribution:
            return SignatureContribution(
                net_call_patterns={".py": [r"evil_sdk\\.call\\b"]},
                persistence_patterns=[r"crontab.*evil\\.sh"],
            )
    """

    net_call_patterns: dict[str, list[str]] = field(default_factory=dict)
    obfuscation_patterns: dict[str, list[str]] = field(default_factory=dict)
    persistence_patterns: list[str] = field(default_factory=list)
    suspicious_package_files: list[str] = field(default_factory=list)
    suspicious_package_prefixes: list[str] = field(default_factory=list)
    dangerous_binary_suffixes: list[str] = field(default_factory=list)
    install_hook_names: list[str] = field(default_factory=list)
    npm_install_scripts: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Load built-in YAML into a mutable accumulator
# ---------------------------------------------------------------------------

_nc = _load(_DIR / "net_calls.yaml")
_ob = _load(_DIR / "obfuscation.yaml")
_pe = _load(_DIR / "persistence.yaml")
_ft = _load(_DIR / "file_types.yaml")

_acc: dict = {
    "net_calls": dict(_nc),
    "obfuscation": dict(_ob["patterns"]),
    "persistence": list(_pe["patterns"]),
    "suspicious_files": list(_ft["suspicious_filenames"]),
    "suspicious_prefixes": list(_ft["suspicious_path_prefixes"]),
    "dangerous_binary": list(_ft["dangerous_binary_suffixes"]),
    "install_hooks": list(_ft["install_hook_names"]),
    "npm_install_scripts": list(_ft["npm_install_scripts"]),
}

# ---------------------------------------------------------------------------
# Discover and merge plugins
# ---------------------------------------------------------------------------


def _load_plugins(acc: dict) -> None:
    try:
        from importlib.metadata import entry_points

        for ep in entry_points(group="dependency_scout.signatures"):
            try:
                _merge_yaml_dir(Path(ep.load()()), acc)
            except Exception:  # noqa: BLE001
                _log.warning("Failed to load signature directory from entry point %r", ep.name)

        for ep in entry_points(group="dependency_scout.signature_providers"):
            try:
                _merge_contribution(ep.load()(), acc)
            except Exception:  # noqa: BLE001
                _log.warning("Failed to load signature provider entry point %r", ep.name)

    except Exception:  # noqa: BLE001
        pass


_load_plugins(_acc)

# ---------------------------------------------------------------------------
# Compile and export constants
# ---------------------------------------------------------------------------

NET_CALL_PATTERNS: dict[str, list[re.Pattern[str]]] = _compile_by_ext(_acc["net_calls"])
OBFUSCATION_PATTERNS: dict[str, list[re.Pattern[str]]] = _compile_by_ext(_acc["obfuscation"])
OBFUSCATION_LINE_THRESHOLD: int = _ob["line_length_threshold"]
GZIP_B64_RE: re.Pattern[str] = re.compile(_ob["gzip_b64"]["pattern"])
GZIP_B64_EXTENSIONS: frozenset[str] = frozenset(_ob["gzip_b64"]["extensions"])
ZERO_WIDTH_RE: re.Pattern[str] = re.compile(_ob["zero_width"]["pattern"])
ZERO_WIDTH_SOURCE_EXTENSIONS: frozenset[str] = frozenset(_ob["zero_width"]["extensions"])
PERSISTENCE_PATTERNS: list[re.Pattern[str]] = _compile_list(_acc["persistence"])
NPM_CRED_READ_RE: re.Pattern[str] = re.compile(
    _pe["worm_propagation"]["credential_read"]["pattern"], re.IGNORECASE
)
NPM_PUBLISH_RE: re.Pattern[str] = re.compile(
    _pe["worm_propagation"]["publish_endpoint"]["pattern"], re.IGNORECASE
)
SUSPICIOUS_PACKAGE_FILES: frozenset[str] = frozenset(_acc["suspicious_files"])
SUSPICIOUS_PACKAGE_PREFIXES: frozenset[str] = frozenset(_acc["suspicious_prefixes"])
DANGEROUS_BINARY_SUFFIXES: frozenset[str] = frozenset(_acc["dangerous_binary"])
INSTALL_HOOK_NAMES: set[str] = set(_acc["install_hooks"])
NPM_INSTALL_SCRIPTS: set[str] = set(_acc["npm_install_scripts"])
