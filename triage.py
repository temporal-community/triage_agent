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


def _label(verdict: str) -> str:
    colors = {"green": "\033[32m", "yellow": "\033[33m", "red": "\033[31m"}
    reset = "\033[0m"
    c = colors.get(verdict, "")
    return f"{c}{verdict.upper()}{reset}"


async def run(ecosystem: str, package: str, old_version: str, new_version: str) -> None:
    env = ActivityEnvironment()
    args = [ecosystem, package, old_version, new_version]

    print(f"\nTriaging {package}  {old_version} → {new_version}  ({ecosystem})\n")

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

    # Print a brief summary of each check result.
    m = pkg.metadata
    checks_summary = [
        (
            "metadata",
            f"{m.weekly_downloads:,} weekly downloads"
            if m.weekly_downloads
            else "no download data",
        ),
        (
            "socket",
            f"score {pkg.socket.socket_score}/100"
            if pkg.socket.socket_score is not None
            else "no data",
        ),
        (
            "osv",
            f"{len(pkg.osv.osv_vulnerabilities)} known vulnerabilities"
            if pkg.osv.osv_vulnerabilities
            else "no known vulnerabilities",
        ),
        (
            "diff",
            "install script added" if pkg.diff.install_script_added else "no suspicious patterns",
        ),
        (
            "maintainer",
            "maintainer changed" if pkg.maintainer.maintainer_changed else "no maintainer changes",
        ),
        (
            "age",
            f"released {pkg.age.release_age_hours:.0f}h ago"
            if pkg.age.release_age_hours
            else "release age unknown",
        ),
        (
            "attestation",
            "build-origin verified" if pkg.attestation.has_attestation else "no attestation",
        ),
        (
            "release_notes",
            "release found" if pkg.release.github_release_exists else "no GitHub release",
        ),
        (
            "version_lineage",
            "on latest version line"
            if not pkg.version_lineage.stale_version_line
            else "stale version line",
        ),
        (
            "deps_dev",
            "deprecated: " + (pkg.deps_dev.deprecated_reason or "yes")
            if pkg.deps_dev.is_deprecated
            else "not deprecated",
        ),
        (
            "scorecard",
            f"score {pkg.scorecard.scorecard_score:.1f}/10"
            if pkg.scorecard.scorecard_score
            else "no scorecard data",
        ),
    ]
    width = max(len(name) for name, _ in checks_summary)
    for name, summary in checks_summary:
        print(f"  {name:<{width}}  {summary}")

    print(f"\nVerdict: {_label(verdict.classification)}  (confidence {verdict.confidence:.0%})\n")
    print(f"  {verdict.reasoning}\n")
    if verdict.flags:
        for flag in verdict.flags:
            print(f"  ! {flag}")
        print()

    print("─" * 60)
    print("To run this automatically on every PR with durable retry,")
    print("auto-merge, and human-approval: see docs/deployment.md")
    print("─" * 60)


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
