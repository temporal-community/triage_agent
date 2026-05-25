"""
Detection pattern loader.

Loads all YAML detection files at import time, compiles regexes, and exports
named constants that mirror the original names in checks/package_diff.py.

To add a new attack pattern: edit the appropriate YAML file — no Python required.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

_DIR = Path(__file__).parent


def _load(name: str) -> Any:
    with open(_DIR / name) as f:
        return yaml.safe_load(f)


def _compile_by_ext(raw: dict) -> dict[str, list[re.Pattern[str]]]:
    return {
        ext: [re.compile(e["pattern"] if isinstance(e, dict) else e) for e in entries]
        for ext, entries in raw.items()
        if entries  # skip null/empty extension entries
    }


# ---------------------------------------------------------------------------
# Network calls
# ---------------------------------------------------------------------------

_nc = _load("net_calls.yaml")
NET_CALL_PATTERNS: dict[str, list[re.Pattern[str]]] = _compile_by_ext(_nc)

# ---------------------------------------------------------------------------
# Obfuscation
# ---------------------------------------------------------------------------

_ob = _load("obfuscation.yaml")
OBFUSCATION_PATTERNS: dict[str, list[re.Pattern[str]]] = _compile_by_ext(_ob["patterns"])
OBFUSCATION_LINE_THRESHOLD: int = _ob["line_length_threshold"]
GZIP_B64_RE: re.Pattern[str] = re.compile(_ob["gzip_b64"]["pattern"])
GZIP_B64_EXTENSIONS: frozenset[str] = frozenset(_ob["gzip_b64"]["extensions"])
ZERO_WIDTH_RE: re.Pattern[str] = re.compile(_ob["zero_width"]["pattern"])
ZERO_WIDTH_SOURCE_EXTENSIONS: frozenset[str] = frozenset(_ob["zero_width"]["extensions"])

# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

_pe = _load("persistence.yaml")
PERSISTENCE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(e["pattern"] if isinstance(e, dict) else e) for e in _pe["patterns"]
]
NPM_CRED_READ_RE: re.Pattern[str] = re.compile(
    _pe["worm_propagation"]["credential_read"]["pattern"], re.IGNORECASE
)
NPM_PUBLISH_RE: re.Pattern[str] = re.compile(
    _pe["worm_propagation"]["publish_endpoint"]["pattern"], re.IGNORECASE
)

# ---------------------------------------------------------------------------
# File types
# ---------------------------------------------------------------------------

_ft = _load("file_types.yaml")
SUSPICIOUS_PACKAGE_FILES: frozenset[str] = frozenset(_ft["suspicious_filenames"])
SUSPICIOUS_PACKAGE_PREFIXES: frozenset[str] = frozenset(_ft["suspicious_path_prefixes"])
DANGEROUS_BINARY_SUFFIXES: frozenset[str] = frozenset(_ft["dangerous_binary_suffixes"])
INSTALL_HOOK_NAMES: set[str] = set(_ft["install_hook_names"])
NPM_INSTALL_SCRIPTS: set[str] = set(_ft["npm_install_scripts"])
