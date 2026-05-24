"""
BotParser protocol — abstracts which bots the agent handles and how to parse their PRs.

Built-in parsers: DependabotParser (handles dependabot[bot]),
                  RenovateParser   (handles renovate[bot]).

To add support for a new bot (PyUp, a private enterprise bot, etc.):
    1. Create a class with bot_logins: frozenset[str] and a parse() method
    2. Call register_bot_parser(MyParser()) at import time (e.g. in an entrypoint)

The webhook uses get_bot_parser(login) to filter events and pick the right parser.
"""

from __future__ import annotations

from typing import Protocol

from helpers.pr_parser import ParsedPR, parse_pr


class BotParser(Protocol):
    """Handles PR title/body parsing for a specific dependency-update bot."""

    bot_logins: frozenset[str]

    def parse(self, title: str, body: str, branch: str) -> ParsedPR | None: ...


class DependabotParser:
    """Parses Dependabot PR titles: 'Bump X from Y to Z'."""

    bot_logins: frozenset[str] = frozenset({"dependabot[bot]"})

    def parse(self, title: str, body: str, branch: str) -> ParsedPR | None:
        return parse_pr(title, body, branch=branch)


class RenovateParser:
    """Parses Renovate PR titles: 'Update dependency X to vY'."""

    bot_logins: frozenset[str] = frozenset({"renovate[bot]"})

    def parse(self, title: str, body: str, branch: str) -> ParsedPR | None:
        return parse_pr(title, body, branch=branch)


_REGISTRY: dict[str, BotParser] = {}


def _build_registry() -> None:
    for parser in (DependabotParser(), RenovateParser()):
        for login in parser.bot_logins:
            _REGISTRY[login] = parser


def register_bot_parser(parser: BotParser) -> None:
    """Register a custom bot parser — call at import time to add a new bot.

    Example:
        class PyUpParser:
            bot_logins = frozenset({"pyup-bot"})
            def parse(self, title, body, branch):
                ...
        register_bot_parser(PyUpParser())
    """
    for login in parser.bot_logins:
        _REGISTRY[login] = parser


def get_bot_parser(login: str) -> BotParser | None:
    """Return the BotParser for this login, or None if it's not a known bot."""
    if not _REGISTRY:
        _build_registry()
    return _REGISTRY.get(login)


def get_bot_logins() -> frozenset[str]:
    """Return the set of all known bot logins."""
    if not _REGISTRY:
        _build_registry()
    return frozenset(_REGISTRY.keys())
