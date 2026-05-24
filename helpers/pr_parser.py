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

Ecosystem detection (in priority order):
  1. Dependabot branch name  — dependabot/npm_and_yarn/... → npm, dependabot/pip/... → pip
  2. Scoped package name     — @org/pkg is always npm
  3. Default                 — pip
"""
import re
from dataclasses import dataclass
from typing import Literal

# Maps Dependabot's internal ecosystem slugs to our ecosystem strings.
# Add new entries here as more ecosystems are supported.
_DEPENDABOT_ECOSYSTEM_MAP: dict[str, Literal["pip", "npm", "rubygems", "maven", "composer"]] = {
    "npm_and_yarn": "npm",
    "pip": "pip",
    "bundler": "rubygems",
    "maven": "maven",
    "composer": "composer",
}


@dataclass
class ParsedPR:
    package: str
    old_version: str
    new_version: str
    ecosystem: Literal["pip", "npm", "rubygems", "maven", "composer"] = "pip"


# @? allows scoped npm packages: @typescript-eslint/parser
# [^`\s]+ is broad enough to capture Maven coordinates (groupId:artifactId)
_DEPENDABOT_RE = re.compile(
    r"[Bb]ump (?P<pkg>@?[^\s`]+) from (?P<old>[\w.\-]+) to (?P<new>[\w.\-]+)",
    re.IGNORECASE,
)

_RENOVATE_RE = re.compile(
    r"[Uu]pdate dependency (?P<pkg>@?[\w.\-\[\]/]+) to v?(?P<new>[\w.\-]+)",
    re.IGNORECASE,
)

_RENOVATE_OLD_RE = re.compile(
    r"from\s+`?(?P<old>[\w.\-]+)`?\s+to\s+`?(?P<new>[\w.\-]+)`?",
    re.IGNORECASE,
)


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
        old = _extract_renovate_old_version(body, pkg)
        return ParsedPR(
            package=pkg,
            old_version=old or "unknown",
            new_version=m.group("new"),
            ecosystem=_detect_ecosystem(pkg, branch),
        )

    return None


def _detect_ecosystem(package: str, branch: str) -> Literal["pip", "npm", "rubygems", "maven", "composer"]:
    # Dependabot branch names encode ecosystem: dependabot/{ecosystem}/{rest}
    if branch.startswith("dependabot/"):
        parts = branch.split("/")
        if len(parts) >= 2:
            slug = parts[1]
            if slug in _DEPENDABOT_ECOSYSTEM_MAP:
                return _DEPENDABOT_ECOSYSTEM_MAP[slug]

    # Scoped npm packages are unambiguous regardless of bot
    if package.startswith("@"):
        return "npm"

    return "pip"


def _extract_renovate_old_version(body: str, package: str) -> str | None:
    """Renovate embeds structured metadata in the PR body as an HTML comment."""
    for line in body.splitlines():
        if package in line:
            m = _RENOVATE_OLD_RE.search(line)
            if m:
                return m.group("old")
    return None
