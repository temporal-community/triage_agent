"""
Extracts package name and versions from Dependabot / Renovate PR titles and bodies.

Dependabot title examples:
  "Bump requests from 2.31.0 to 2.32.0"
  "Bump requests from 2.31.0 to 2.32.0 in /subdir"
  "build(deps): bump requests from 2.31.0 to 2.32.0"

Renovate title examples:
  "Update dependency requests to v2.32.0"
  "chore(deps): update dependency requests to 2.32.0"
"""
import re
from dataclasses import dataclass


@dataclass
class ParsedPR:
    package: str
    old_version: str
    new_version: str
    ecosystem: str = "pip"


_DEPENDABOT_RE = re.compile(
    r"[Bb]ump (?P<pkg>[\w./\-\[\]]+) from (?P<old>[\w.\-]+) to (?P<new>[\w.\-]+)",
    re.IGNORECASE,
)

_RENOVATE_RE = re.compile(
    r"[Uu]pdate dependency (?P<pkg>[\w.\-\[\]]+) to v?(?P<new>[\w.\-]+)",
    re.IGNORECASE,
)

_RENOVATE_OLD_RE = re.compile(
    r"from\s+`?(?P<old>[\w.\-]+)`?\s+to\s+`?(?P<new>[\w.\-]+)`?",
    re.IGNORECASE,
)


def parse_pr(title: str, body: str = "") -> ParsedPR | None:
    m = _DEPENDABOT_RE.search(title)
    if m:
        return ParsedPR(
            package=m.group("pkg"),
            old_version=m.group("old"),
            new_version=m.group("new"),
        )

    m = _RENOVATE_RE.search(title)
    if m:
        old = _extract_renovate_old_version(body, m.group("pkg"))
        return ParsedPR(
            package=m.group("pkg"),
            old_version=old or "unknown",
            new_version=m.group("new"),
        )

    return None


def _extract_renovate_old_version(body: str, package: str) -> str | None:
    """Renovate embeds structured metadata in the PR body as an HTML comment."""
    for line in body.splitlines():
        if package in line:
            m = _RENOVATE_OLD_RE.search(line)
            if m:
                return m.group("old")
    return None
