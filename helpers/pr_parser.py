"""
Extracts package name, versions, and ecosystem from Dependabot / Renovate PR titles and bodies.

Dependabot title examples:
  "Bump requests from 2.31.0 to 2.32.0"
  "Bump requests from 2.31.0 to 2.32.0 in /subdir"
  "build(deps): bump lodash from 4.17.20 to 4.17.21"
  "Bump @typescript-eslint/parser from 6.0.0 to 6.1.0"

Renovate title examples:
  "Update dependency requests to v2.32.0"
  "chore(deps): update dependency lodash to 4.17.21"
  "Update dependency @typescript-eslint/eslint-plugin to v6.1.0"
  "Update requests to v2.32.0"                         (no "dependency" keyword)
  "fix(deps): Update requests to 2.32.0"

Ecosystem detection (in priority order):
  1. Dependabot branch name  — dependabot/npm_and_yarn/... → npm, dependabot/pip/... → pip
  2. Renovate branch name    — renovate/npm-..., renovate/python-..., renovate/cargo-..., etc.
  3. Scoped package name     — @org/pkg is always npm
  4. Default                 — pip
"""

import re
from dataclasses import dataclass

from activities.ecosystems import get_dependabot_slug_map

# Renovate embeds manager/datasource names in branch prefixes when users customize
# branchName templates (e.g. renovate/npm-lodash-4.x, renovate/python-requests-2.x).
# Maps the segment prefix (before the first "-") to our ecosystem name.
_RENOVATE_SLUG_MAP: dict[str, str] = {
    # npm / JavaScript
    "npm": "npm",
    "node": "npm",
    # Python
    "pypi": "pip",
    "python": "pip",
    # Ruby
    "bundler": "rubygems",
    "gem": "rubygems",
    "ruby": "rubygems",
    # JVM
    "maven": "maven",
    "gradle": "maven",
    # Rust
    "cargo": "cargo",
    # Go
    "golang": "go",
    "gomod": "go",
    # .NET
    "nuget": "nuget",
    # PHP
    "composer": "composer",
}


@dataclass
class ParsedPR:
    package: str
    old_version: str
    new_version: str
    ecosystem: str = "pip"


# @? allows scoped npm packages: @typescript-eslint/parser
# [^`\s]+ is broad enough to capture Maven coordinates (groupId:artifactId)
_DEPENDABOT_RE = re.compile(
    r"[Bb]ump (?P<pkg>@?[^\s`]+) from (?P<old>[\w.\-]+) to (?P<new>[\w.\-]+)",
    re.IGNORECASE,
)

# "dependency" is optional — some Renovate presets omit it.
# New version must start with a digit so we don't match "Update README to fix typo".
_RENOVATE_RE = re.compile(
    r"[Uu]pdate\s+(?:dependency\s+)?(?P<pkg>@?[\w.\-\[\]/]+)\s+to\s+v?(?P<new>\d[\w.\-]*)",
    re.IGNORECASE,
)

# Broad version pattern for body extraction: covers pre-release and build metadata.
_VER = r"[\w.\-+]+"

# "`old` -> `new`" or "old → new" — the most common Renovate table format.
_ARROW_RE = re.compile(
    r"`?(?P<old>" + _VER + r")`?\s*(?:->|→)\s*`?(?P<new>" + _VER + r")`?"
)

# "from `old` to `new`" — used in Renovate body prose and some table formats.
_FROM_TO_RE = re.compile(
    r"from\s+`?(?P<old>" + _VER + r")`?\s+to\s+`?(?P<new>" + _VER + r")`?",
    re.IGNORECASE,
)


def _normalize_ver(v: str) -> str:
    return v.lstrip("v")


def parse_pr(title: str, body: str = "", branch: str = "") -> ParsedPR | None:
    m = _DEPENDABOT_RE.search(title)
    if m:
        pkg = m.group("pkg")
        return ParsedPR(
            package=pkg,
            old_version=m.group("old"),
            new_version=m.group("new"),
            ecosystem=_detect_ecosystem(pkg, branch),
        )

    m = _RENOVATE_RE.search(title)
    if m:
        pkg = m.group("pkg")
        new = m.group("new")
        old = _extract_renovate_old_version(body, pkg, new)
        return ParsedPR(
            package=pkg,
            old_version=old or "unknown",
            new_version=new,
            ecosystem=_detect_ecosystem(pkg, branch),
        )

    return None


def _detect_ecosystem(package: str, branch: str) -> str:
    # Dependabot branch names encode ecosystem: dependabot/{ecosystem}/{rest}
    if branch.startswith("dependabot/"):
        parts = branch.split("/")
        if len(parts) >= 2:
            slug = parts[1]
            slug_map = get_dependabot_slug_map()
            if slug in slug_map:
                return slug_map[slug]

    # Renovate branch names sometimes encode the manager/datasource as a prefix:
    # renovate/{manager}-{package}-{version}.x  (e.g. renovate/npm-lodash-4.x)
    elif branch.startswith("renovate/"):
        seg = branch[len("renovate/"):]
        prefix = seg.split("-")[0]
        if prefix in _RENOVATE_SLUG_MAP:
            return _RENOVATE_SLUG_MAP[prefix]

    # Scoped npm packages are unambiguous regardless of bot
    if package.startswith("@"):
        return "npm"

    return "pip"


def _extract_renovate_old_version(body: str, package: str, new_version: str) -> str | None:
    """Extract old version from a Renovate PR body using multiple strategies.

    Strategy 1: line containing the package name + arrow pattern  (`old` -> `new`)
    Strategy 2: line containing the package name + from/to pattern (from `old` to `new`)
    Strategy 3: any line with a matching transition (no package name required) —
                fallback for bodies where the package name appears differently than
                in the title (e.g. fully-qualified vs short name).

    In all strategies the extracted new version is cross-checked against the known
    new version (modulo leading `v`) to avoid picking up unrelated transitions.
    """
    norm_new = _normalize_ver(new_version)
    lines = body.splitlines()

    # Negative lookbehind/lookahead on alphanumeric + hyphen prevents substring
    # matches: package "xml" will not match "xmltodict", "lxml", or "xml-js".
    pkg_re = re.compile(
        r"(?<![a-zA-Z0-9_\-])" + re.escape(package) + r"(?![a-zA-Z0-9_\-])",
        re.IGNORECASE,
    )

    # Strategies 1 & 2: prefer lines that mention the package name.
    for line in lines:
        if not pkg_re.search(line):
            continue
        for pattern in (_ARROW_RE, _FROM_TO_RE):
            m = pattern.search(line)
            if m and _normalize_ver(m.group("new")) == norm_new:
                return m.group("old")

    # Strategy 3: any line whose transition ends at the known new version.
    for line in lines:
        for pattern in (_ARROW_RE, _FROM_TO_RE):
            m = pattern.search(line)
            if m and _normalize_ver(m.group("new")) == norm_new:
                return m.group("old")

    return None
