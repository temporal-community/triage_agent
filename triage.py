#!/usr/bin/env python3
"""
Triage a dependency bump directly — no Temporal worker or server required.

Usage:
    uv run python triage.py https://github.com/owner/repo/pull/123
    uv run python triage.py --ecosystem pip --package requests --old 2.31.0 --new 2.32.0

Set GITHUB_TOKEN in .env (or environment) for higher API rate limits and private repos.
Set ANTHROPIC_API_KEY to use Claude for classification; without it, rule-based fallback is used.

For automated triage on every PR — with durable retry, auto-merge, and the human-approval
loop — see docs/deployment.md to set up the full Temporal worker.
"""

import argparse
import asyncio
import logging
import os
import re
import sys

import httpx
from checks import (
    attestation,
    classifier as _classifier_mod,
    custom_checks,
    depsdev,
    maintainer,
    metadata,
    osv,
    package_diff,
    release_age,
    release_notes,
    scorecard,
    socket,
    version_lineage,
)
from dotenv import load_dotenv
from helpers.pr_parser import parse_pr
from models import CheckContext, PackageChecks
from temporalio.testing import ActivityEnvironment

load_dotenv()

logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")

_GITHUB_PR_RE = re.compile(r"github\.com/([^/]+/[^/]+)/pull/(\d+)")

_CHECKS = [
    ("metadata", metadata.fetch),
    ("socket", socket.score),
    ("osv", osv.check),
    ("diff", package_diff.compute),
    ("maintainer", maintainer.history),
    ("age", release_age.check),
    ("attestation", attestation.check),
    ("release_notes", release_notes.check),
    ("version_lineage", version_lineage.check),
    ("deps_dev", depsdev.fetch),
    ("scorecard", scorecard.fetch),
]


async def _fetch_pr(url: str) -> tuple[str, str, str, str]:
    """Return (ecosystem, package, old_version, new_version) by querying GitHub."""
    m = _GITHUB_PR_RE.search(url)
    if not m:
        sys.exit(f"Unrecognized PR URL: {url!r}  (expected https://github.com/owner/repo/pull/N)")
    owner_repo, pr_num = m.group(1), m.group(2)

    headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(
            f"https://api.github.com/repos/{owner_repo}/pulls/{pr_num}",
            headers=headers,
        )
    if resp.status_code == 404:
        sys.exit(f"PR not found: {url}  (private repo? set GITHUB_TOKEN)")
    if resp.status_code != 200:
        sys.exit(f"GitHub API error {resp.status_code} fetching {url}")

    data = resp.json()
    parsed = parse_pr(
        title=data.get("title", ""),
        body=data.get("body", "") or "",
        branch=data["head"]["ref"],
    )
    if not parsed:
        sys.exit(
            f"Could not parse ecosystem/package/versions from PR title: {data.get('title')!r}\n"
            "Use --ecosystem, --package, --old, --new instead."
        )
    return parsed.ecosystem, parsed.package, parsed.old_version, parsed.new_version


# ---------------------------------------------------------------------------
# Terminal output helpers
# ---------------------------------------------------------------------------

_G = "\033[32m"
_Y = "\033[33m"
_R = "\033[31m"
_C = "\033[36m"  # cyan — actionable but non-alarming (e.g. missing optional API key)
_DIM = "\033[2m"
_B = "\033[1m"
_RST = "\033[0m"


def _g(s: str) -> str:
    return f"{_G}{s}{_RST}"


def _y(s: str) -> str:
    return f"{_Y}{s}{_RST}"


def _r(s: str) -> str:
    return f"{_R}{s}{_RST}"


def _c(s: str) -> str:
    return f"{_C}{s}{_RST}"


def _dim(s: str) -> str:
    return f"{_DIM}{s}{_RST}"


def _first_para(text: str, max_chars: int = 300) -> str:
    """Return the first paragraph, or first ~300 chars ending on a sentence boundary."""
    end = text.find("\n\n")
    if 0 < end < max_chars + 100:
        return text[:end].strip()
    if len(text) <= max_chars:
        return text
    cut = text[:max_chars]
    dot = max(cut.rfind(". "), cut.rfind(".\n"))
    return (cut[: dot + 1] if dot > max_chars // 2 else cut) + " …"


# (terminal icon, markdown icon, text-colouring function)
_STATUS: dict[str, tuple[str, str, object]] = {
    "ok": (_g("✓"), "✅", _g),
    "bad": (_r("✗"), "❌", _r),
    "warn": (_y("!"), "⚠️", _y),
    "na": (_dim("─"), "—", _dim),
    "info": (_c("ℹ"), "ℹ️", _c),  # optional improvement available
    "fail": (_y("!"), "⚠️", _y),
}

_VERDICT_EMOJI = {"green": "🟢", "yellow": "🟡", "red": "🔴"}
_VERDICT_COLOR = {"green": _G, "yellow": _Y, "red": _R}


def _verdict_label(v: str) -> str:
    e = _VERDICT_EMOJI.get(v, "")
    c = _VERDICT_COLOR.get(v, "")
    return f"{e} {c}{_B}{v.upper()}{_RST}"


async def run(ecosystem: str, package: str, old_version: str, new_version: str) -> None:
    from ecosystems import get_dependabot_slug_map, get_provider

    try:
        get_provider(ecosystem)
    except ValueError:
        supported = ", ".join(sorted(get_dependabot_slug_map().values()))
        sys.exit(
            f"Ecosystem {ecosystem!r} is not supported by dependency-scout.\n"
            f"Supported ecosystems: {supported}"
        )

    # --- Environment rows (no activity results needed) ----------------------
    has_socket_key = bool(os.environ.get("SOCKET_API_KEY"))
    has_llm_key = bool(
        os.environ.get("ANTHROPIC_API_KEY")
        or os.environ.get("OPENAI_API_KEY")
        or os.environ.get("OLLAMA_HOST")
        or os.environ.get("CLASSIFIER")
    )

    if has_llm_key:
        from classifiers import get_classifier

        clf_name = type(get_classifier()).__name__.replace("Classifier", "")
    else:
        clf_name = None

    setup_rows = [
        (
            "ok",
            "Core checks",
            "OSV, diff analysis, release age, maintainer history, version lineage, and more",
        ),
        (
            "ok" if has_socket_key else "info",
            "Socket.dev",
            "Supply-chain threat intelligence"
            + ("" if has_socket_key else " — add SOCKET_API_KEY to .env  (socket.dev)"),
        ),
        (
            "ok" if clf_name else "info",
            "Classifier",
            f"{clf_name} — LLM-powered GREEN/YELLOW/RED verdict"
            if clf_name
            else "Rule-based fallback — add ANTHROPIC_API_KEY to .env for LLM analysis",
        ),
    ]

    print(_dim("Running the following checks:\n"))
    w = max(len(label) for _, label, _ in setup_rows)
    for status, label, desc in setup_rows:
        icon_ansi, _, text_fn = _STATUS[status]
        print(f"  {icon_ansi}  {label:<{w}}  {text_fn(desc)}")  # type: ignore[operator]
    print(_dim("\n  See docs/configuration.md for setup details."))
    print(_dim("\n" + "─" * 60))
    print()

    # --- Per-release checks --------------------------------------------------
    env = ActivityEnvironment()
    args = [ecosystem, package, old_version, new_version]

    print(f"Triaging {package}  {old_version} → {new_version}  ({ecosystem})\n")

    # Run all 11 checks in parallel, degrading gracefully on failure.
    raw = await asyncio.gather(
        *(env.run(fn, *args) for _, fn in _CHECKS),
        return_exceptions=True,
    )
    check_kwargs: dict = {}
    for (field, _), result in zip(_CHECKS, raw):
        if isinstance(result, Exception):
            logging.warning("Check %r failed: %r — using defaults", field, result)
            check_kwargs[field] = None
        else:
            check_kwargs[field] = result

    ctx = CheckContext(
        package=package,
        ecosystem=ecosystem,
        old_version=old_version,
        new_version=new_version,
    )
    custom = await env.run(custom_checks.run_all, ctx)

    pkg = PackageChecks(
        ecosystem=ecosystem,
        package_name=package,
        old_version=old_version,
        new_version=new_version,
        custom_checks=custom,
        **{k: v for k, v in check_kwargs.items() if v is not None},
    )

    verdict = await env.run(_classifier_mod.classify, pkg)

    # Determine which checks raised exceptions (vs returned degraded defaults).
    failed = {field for (field, _), result in zip(_CHECKS, raw) if isinstance(result, Exception)}

    # Build rows: (name, status, plain_text)
    # status ∈ {"ok", "bad", "warn", "na", "fail"}
    m = pkg.metadata
    rows: list[tuple[str, str, str]] = []

    def _row(name: str, status: str, text: str) -> None:
        rows.append((name, "fail" if name in failed else status, text))

    h = pkg.age.release_age_hours
    if m.weekly_downloads is not None:
        _row("metadata", "na", f"{m.weekly_downloads:,} weekly downloads")
    else:
        _row("metadata", "na", "N/A — no download data for this ecosystem")

    if has_socket_key:
        if pkg.socket.socket_score is not None:
            s = pkg.socket.socket_score
            _row("socket", "ok" if s >= 70 else ("warn" if s >= 40 else "bad"), f"score {s}/100")
        else:
            _row("socket", "na", "no data")

    if pkg.osv.osv_vulnerabilities:
        _row("osv", "bad", f"{len(pkg.osv.osv_vulnerabilities)} known vulnerabilities")
    else:
        _row("osv", "ok", "no known vulnerabilities")

    if pkg.diff.install_script_added:
        _row("diff", "bad", "install script added")
    else:
        _row("diff", "ok", "no suspicious patterns")

    if pkg.maintainer.maintainer_changed:
        _row("maintainer", "warn", "maintainer changed")
    else:
        _row("maintainer", "ok", "no changes detected")

    if h is not None:
        age_status = "warn" if h < 168 else "ok"
        _row("age", age_status, f"released {h:.0f}h ago")
    else:
        _row("age", "na", "release age unknown")

    if pkg.attestation.has_attestation:
        _row("attestation", "ok", "build provenance verified")
    else:
        _row("attestation", "na", "N/A — no build provenance")

    if pkg.release.github_release_exists:
        _row("release_notes", "ok", "GitHub release found")
    else:
        _row("release_notes", "na", "N/A — no GitHub release")

    if pkg.version_lineage.stale_version_line:
        _row("version_lineage", "warn", "stale version line")
    else:
        _row("version_lineage", "ok", "on latest version line")

    if pkg.deps_dev.is_deprecated:
        _row("deps_dev", "bad", "deprecated: " + (pkg.deps_dev.deprecated_reason or "yes"))
    else:
        _row("deps_dev", "ok", "not deprecated")

    if pkg.scorecard.scorecard_score is not None:
        sc = pkg.scorecard.scorecard_score
        _row("scorecard", "ok" if sc >= 7 else ("warn" if sc >= 4 else "bad"), f"score {sc:.1f}/10")
    else:
        _row("scorecard", "na", "N/A — not in Scorecard database")

    # Print check summary.
    width = max(len(name) for name, _, _ in rows)
    for name, status, text in rows:
        icon_ansi, _, text_fn = _STATUS[status]
        print(f"  {name:<{width}}  {icon_ansi}  {text_fn(text)}")  # type: ignore[operator]

    # Verdict + brief reasoning.
    v = verdict.classification
    print(f"\nVerdict: {_verdict_label(v)}  (confidence {verdict.confidence:.0%})\n")
    print(f"  {_first_para(verdict.reasoning)}\n")
    if verdict.flags:
        for flag in verdict.flags:
            print(f"  {_y('⚠')} {flag}")
        print()

    print(_dim("─" * 60))
    print(_dim("dependency-scout  ·  docs/deployment.md  ·  temporal.io"))
    print(_dim("─" * 60))


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="Triage a dependency bump without a running Temporal worker."
    )
    parser.add_argument("pr_url", nargs="?", help="GitHub PR URL")
    parser.add_argument("--ecosystem", help="e.g. pip, npm, cargo")
    parser.add_argument("--package", help="e.g. requests, lodash")
    parser.add_argument("--old", dest="old_version", metavar="VERSION")
    parser.add_argument("--new", dest="new_version", metavar="VERSION")
    args = parser.parse_args()

    if args.pr_url:
        ecosystem, package, old_version, new_version = await _fetch_pr(args.pr_url)
    elif all([args.ecosystem, args.package, args.old_version, args.new_version]):
        ecosystem = args.ecosystem
        package = args.package
        old_version = args.old_version
        new_version = args.new_version
    else:
        parser.print_help()
        sys.exit(1)

    await run(ecosystem, package, old_version, new_version)


if __name__ == "__main__":
    asyncio.run(main())
