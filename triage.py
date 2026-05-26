#!/usr/bin/env python3
"""
Triage Dependabot/Renovate PRs via the dependency-scout Temporal worker.

Single PR:
    uv run python -m triage https://github.com/owner/repo/pull/123

All open PRs in a repo:
    uv run python -m triage --repo owner/repo

Specific PRs:
    uv run python -m triage --repo owner/repo --prs 12,33,64

First N PRs:
    uv run python -m triage --repo owner/repo --limit 5

Add --dry-run to any command to skip posting comments or taking actions.

Requires a running Temporal worker:
    temporal server start-dev    # Terminal 1
    uv run python -m worker      # Terminal 2
"""

from __future__ import annotations

import argparse
import asyncio
from datetime import date
import os
import re
import sys

import httpx
from dotenv import load_dotenv
from temporalio.client import Client, TLSConfig
from temporalio.contrib.pydantic import pydantic_data_converter

from helpers.pr_parser import parse_pr, ParsedPR
from models import PRContext
from workflows.pr_action_workflow import PRActionWorkflow

load_dotenv()

# ---------------------------------------------------------------------------
# Color helpers
# ---------------------------------------------------------------------------

_G = "\033[32m"
_Y = "\033[33m"
_R = "\033[31m"
_C = "\033[36m"
_DIM = "\033[2m"
_B = "\033[1m"
_RST = "\033[0m"


def _g(s: str) -> str:
    return f"{_G}{s}{_RST}"


def _y(s: str) -> str:
    return f"{_Y}{s}{_RST}"


def _r(s: str) -> str:
    return f"{_R}{s}{_RST}"


def _dim(s: str) -> str:
    return f"{_DIM}{s}{_RST}"


def _bold(s: str) -> str:
    return f"{_B}{s}{_RST}"


def _info(s: str) -> str:
    return f"{_C}{s}{_RST}"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_GITHUB_PR_RE = re.compile(r"github\.com/([^/]+/[^/]+)/pull/(\d+)")


async def _connect() -> Client:
    tls: TLSConfig | bool = False
    cert_path = os.environ.get("TEMPORAL_TLS_CERT")
    key_path = os.environ.get("TEMPORAL_TLS_KEY")
    if cert_path and key_path:
        tls = TLSConfig(
            client_cert=open(cert_path, "rb").read(),
            client_private_key=open(key_path, "rb").read(),
        )
    return await Client.connect(
        os.environ.get("TEMPORAL_ADDRESS", "localhost:7233"),
        namespace=os.environ.get("TEMPORAL_NAMESPACE", "default"),
        tls=tls,
        data_converter=pydantic_data_converter,
    )


async def _fetch_pr_data(repo: str, pr_number: int, token: str | None) -> dict:
    headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(
            f"https://api.github.com/repos/{repo}/pulls/{pr_number}",
            headers=headers,
        )
    if resp.status_code == 404:
        sys.exit(f"PR #{pr_number} not found in {repo}  (private repo? set GITHUB_TOKEN)")
    if resp.status_code != 200:
        try:
            detail = resp.json().get("message", resp.text[:200])
        except Exception:
            detail = resp.text[:200]
        sys.exit(f"GitHub API error {resp.status_code} for {repo}#{pr_number}\n  {detail}")
    return resp.json()


async def _list_dependabot_prs(repo: str, token: str | None) -> list[dict]:
    headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    prs = []
    page = 1
    async with httpx.AsyncClient(timeout=15.0) as client:
        while True:
            resp = await client.get(
                f"https://api.github.com/repos/{repo}/pulls",
                headers=headers,
                params={"state": "open", "per_page": 100, "page": page},
            )
            if resp.status_code == 404:
                sys.exit(f"Repo not found: {repo!r}  (private? set GITHUB_TOKEN)")
            resp.raise_for_status()
            batch = resp.json()
            if not batch:
                break
            for pr in batch:
                author = pr.get("user", {}).get("login", "")
                if author in ("dependabot[bot]", "renovate[bot]"):
                    prs.append(pr)
            page += 1
    return prs


def _verdict_from_result(result: str) -> str:
    if "green" in result or result in ("auto-merged", "human-approved-merged"):
        return "green"
    if "red" in result:
        return "red"
    return "yellow"


def _color_verdict(verdict: str) -> str:
    emoji = {"green": "🟢", "yellow": "🟡", "red": "🔴"}[verdict]
    color = {"green": _G, "yellow": _Y, "red": _R}[verdict]
    return f"{emoji} {color}{_B}{verdict.upper()}{_RST}"


def _clf_name() -> str | None:
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "Claude"
    if os.environ.get("OPENAI_API_KEY"):
        return "OpenAI"
    if os.environ.get("OLLAMA_HOST"):
        return "Ollama"
    if os.environ.get("CLASSIFIER"):
        return os.environ["CLASSIFIER"]
    return None


def _env_summary(dry_run: bool, has_github: bool, clf: str | None) -> None:
    if dry_run:
        github_desc = _info("dry-run (--dry-run) — no comments or actions will be taken")
    elif has_github:
        github_desc = _g("will post real comments on PRs")
    else:
        github_desc = _info("dry-run — add GITHUB_TOKEN to .env to post real comments")

    clf_desc = (
        _g(f"{clf} — LLM-powered verdict")
        if clf
        else _info("rule-based fallback — add ANTHROPIC_API_KEY to .env for LLM analysis")
    )
    print(f"  github     {github_desc}")
    print(f"  classifier {clf_desc}")


# ---------------------------------------------------------------------------
# Single-PR mode
# ---------------------------------------------------------------------------


async def _triage_single(args: argparse.Namespace) -> None:
    token = os.environ.get("GITHUB_TOKEN")
    has_github = bool(token)

    if args.pr_url:
        m = _GITHUB_PR_RE.search(args.pr_url)
        if not m:
            sys.exit(
                f"Unrecognized PR URL: {args.pr_url!r}\n"
                "  Expected: https://github.com/owner/repo/pull/N"
            )
        repo = m.group(1)
        pr_number = int(m.group(2))
        data = await _fetch_pr_data(repo, pr_number, token)
        parsed = parse_pr(
            title=data.get("title", ""),
            body=data.get("body", "") or "",
            branch=data["head"]["ref"],
        )
        if not parsed:
            sys.exit(
                f"Could not parse ecosystem/package/versions from PR title: {data.get('title')!r}\n"
                "  Use --package, --old-version, --new-version to specify manually."
            )
        ecosystem = parsed.ecosystem
        package = parsed.package
        old_version = parsed.old_version
        new_version = parsed.new_version
        pr_author = data.get("user", {}).get("login", "dependabot[bot]")
    else:
        # Manual mode: --repo + --package + --old-version + --new-version
        repo = args.repo
        pr_number = args.pr_number or 0
        ecosystem = args.ecosystem
        package = args.package
        old_version = args.old_version
        new_version = args.new_version
        pr_author = "dependabot[bot]"

    clf = _clf_name()
    print(
        f"\n{_bold(f'{repo}#{pr_number}')}  "
        f"{package} {old_version} → {new_version}  "
        f"{_dim(f'({ecosystem})')}\n"
    )
    _env_summary(args.dry_run, has_github, clf)
    print()

    pr = PRContext(
        repo=repo,
        pr_number=pr_number,
        pr_author=pr_author,
        installation_id=args.installation_id or None,
        ecosystem=ecosystem,
        package_name=package,
        old_version=old_version,
        new_version=new_version,
        dry_run=args.dry_run,
    )

    client = await _connect()
    workflow_id = f"pr-action-{repo.replace('/', '-')}-{pr_number}"
    handle = await client.start_workflow(
        PRActionWorkflow.run,
        pr,
        id=workflow_id,
        task_queue=os.environ.get("TEMPORAL_TASK_QUEUE", "dependency-triage"),
    )

    ui_base = os.environ.get("TEMPORAL_UI_BASE_URL", "http://localhost:8233")
    ns = os.environ.get("TEMPORAL_NAMESPACE", "default")
    print(f"  Workflow: {handle.id}")
    wf_url = f"{ui_base}/namespaces/{ns}/workflows/{handle.id}"
    print(f"  Temporal: {wf_url}")
    print()

    result = await handle.result()
    result_str, *url_parts = result.split("||", 1)
    comment_url = url_parts[0] if url_parts else None
    verdict = _verdict_from_result(result_str)
    print(f"  {_color_verdict(verdict)}  {_dim(result_str)}")
    if comment_url:
        print(f"  Comment:  {comment_url}")
    elif not args.dry_run and has_github and pr_number:
        print(f"  PR:       https://github.com/{repo}/pull/{pr_number}")
    print()


# ---------------------------------------------------------------------------
# Batch mode
# ---------------------------------------------------------------------------


async def _triage_one(
    client: Client, repo: str, pr_data: dict, parsed: ParsedPR, dry_run: bool = False
) -> tuple[dict, ParsedPR, str]:
    pr = PRContext(
        repo=repo,
        pr_number=pr_data["number"],
        pr_author=pr_data["user"]["login"],
        ecosystem=parsed.ecosystem,
        package_name=parsed.package,
        old_version=parsed.old_version,
        new_version=parsed.new_version,
        dry_run=dry_run,
    )
    workflow_id = f"pr-action-{repo.replace('/', '-')}-{pr_data['number']}"
    handle = await client.start_workflow(
        PRActionWorkflow.run,
        pr,
        id=workflow_id,
        task_queue=os.environ.get("TEMPORAL_TASK_QUEUE", "dependency-triage"),
    )
    return pr_data, parsed, await handle.result()


async def _cleanup_orphaned_triage_workflows(
    client: Client, parseable: list[tuple[dict, ParsedPR]]
) -> None:
    """Terminate any still-running PackageTriageWorkflow instances for this batch.

    When a PRActionWorkflow fails mid-run its PackageTriageWorkflow children are
    abandoned (ABANDON policy) and keep running. On re-run, execute_child_workflow
    with the same date-keyed ID raises "already started". Terminating orphans here
    (before starting new parents) lets the new parents start fresh children cleanly.
    """
    date_key = date.today().isoformat()
    terminated = 0
    for _, parsed in parseable:
        wf_id = f"triage-{parsed.ecosystem}-{parsed.package}-{parsed.new_version}-{date_key}"
        try:
            handle = client.get_workflow_handle(wf_id)
            await handle.terminate(reason="triage re-run cleanup")
            terminated += 1
        except Exception:
            pass  # not running / already closed — nothing to do
    if terminated:
        print(_dim(f"  Cleaned up {terminated} orphaned triage workflow(s) from a previous run.\n"))


async def _triage_batch(args: argparse.Namespace) -> None:
    token = os.environ.get("GITHUB_TOKEN")
    has_github = bool(token)

    if args.prs:
        pr_numbers = [int(n.strip()) for n in args.prs.split(",") if n.strip()]
        print(_dim(f"Fetching {len(pr_numbers)} specified PR(s) from {args.repo} ..."))
        raw_prs = await asyncio.gather(*[_fetch_pr_data(args.repo, n, token) for n in pr_numbers])
    else:
        print(_dim(f"Fetching open Dependabot/Renovate PRs for {args.repo} ..."))
        raw_prs = await _list_dependabot_prs(args.repo, token)

    parseable: list[tuple[dict, ParsedPR]] = []
    skipped: list[dict] = []
    for pr in raw_prs:
        parsed = parse_pr(
            title=pr.get("title", ""),
            body=pr.get("body", "") or "",
            branch=pr["head"]["ref"],
        )
        if parsed:
            parseable.append((pr, parsed))
        else:
            skipped.append(pr)

    if not parseable:
        print(f"No parseable Dependabot/Renovate PRs found in {args.repo}.")
        return

    if args.limit:
        parseable = parseable[: args.limit]

    print(f"\nFound {_bold(str(len(parseable)))} PR(s) to triage:\n")

    pkg_w = max(len(p.package) for _, p in parseable)
    for pr, parsed in parseable:
        print(
            f"  #{pr['number']:<5} {parsed.package:<{pkg_w}}  "
            f"{parsed.old_version} → {parsed.new_version}  "
            f"{_dim(f'({parsed.ecosystem})')}"
        )

    if skipped:
        print(f"\n  {_dim(f'Skipping {len(skipped)} PR(s) with unparseable titles.')}")

    clf = _clf_name()
    if not clf:
        from classifiers import get_classifier

        clf_name_fallback = type(get_classifier()).__name__.replace("Classifier", "")
        clf = clf_name_fallback if clf_name_fallback != "RuleBased" else None

    print()
    _env_summary(args.dry_run, has_github, clf)
    print(_dim("\n" + "─" * 60 + "\n"))

    client = await _connect()
    await _cleanup_orphaned_triage_workflows(client, parseable)
    tasks = [
        asyncio.create_task(_triage_one(client, args.repo, pr, parsed, dry_run=args.dry_run))
        for pr, parsed in parseable
    ]

    counts: dict[str, int] = {"green": 0, "yellow": 0, "red": 0}
    errors = 0
    ui_base = os.environ.get("TEMPORAL_UI_BASE_URL", "http://localhost:8233")
    ns = os.environ.get("TEMPORAL_NAMESPACE", "default")

    print(f"Triaging {len(tasks)} PR(s) in parallel ...\n")

    for future in asyncio.as_completed(tasks):
        try:
            pr_data, parsed, result = await future
        except Exception as exc:
            errors += 1
            # WorkflowFailureError wraps the real cause — unwrap it for a useful message
            cause = getattr(exc, "cause", None)
            msg = str(cause) if cause else str(exc)
            print(f"\n  {_r(_B + '✗  WORKFLOW FAILED' + _RST)}  {_r(msg)}\n")
            continue

        result_str, *url_parts = result.split("||", 1)
        comment_url = url_parts[0] if url_parts else None
        verdict = _verdict_from_result(result_str)
        counts[verdict] += 1
        pr_url = f"https://github.com/{args.repo}/pull/{pr_data['number']}"
        wf_id = f"pr-action-{args.repo.replace('/', '-')}-{pr_data['number']}"
        print(
            f"  {_color_verdict(verdict)}  "
            f"#{pr_data['number']:<5} {parsed.package:<{pkg_w}}  "
            f"{parsed.old_version} → {parsed.new_version}"
        )
        wf_url = f"{ui_base}/namespaces/{ns}/workflows/{wf_id}"
        if comment_url:
            print(f"        Comment:  {comment_url}")
        else:
            print(f"        PR:       {pr_url}")
        print(f"        Workflow: {wf_url}")

    total = sum(counts.values())
    g, y, r = counts["green"], counts["yellow"], counts["red"]
    summary = (
        f"  {_bold(f'{total} done')}  ·  "
        f"{_g(f'{g} green')}  ·  "
        f"{_y(f'{y} yellow')}  ·  "
        f"{_r(f'{r} red')}"
    )
    if errors:
        summary += f"  ·  {_r(_bold(f'{errors} failed'))}"
    print(_dim("\n" + "─" * 60))
    print(summary)
    print(_dim("─" * 60))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="Triage Dependabot/Renovate PRs via the dependency-scout Temporal worker.",
        epilog=(
            "examples:\n"
            "  triage https://github.com/owner/repo/pull/123\n"
            "  triage --repo owner/repo\n"
            "  triage --repo owner/repo --prs 12,33,64\n"
            "  triage --repo owner/repo --limit 5 --dry-run"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("pr_url", nargs="?", help="GitHub PR URL (single-PR mode)")
    parser.add_argument("--repo", metavar="OWNER/REPO", help="repository to triage")
    parser.add_argument(
        "--prs", metavar="N,N,...", help="comma-separated PR numbers (requires --repo)"
    )
    parser.add_argument(
        "--limit", type=int, metavar="N", help="max PRs to triage (requires --repo)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        dest="dry_run",
        help="triage without posting comments or taking any actions",
    )
    # Manual override flags for testing without a real Dependabot PR
    parser.add_argument("--package", help="package name (manual override)")
    parser.add_argument("--old-version", dest="old_version", help="old version (manual override)")
    parser.add_argument("--new-version", dest="new_version", help="new version (manual override)")
    parser.add_argument("--ecosystem", default="pip", help="ecosystem (default: pip)")
    parser.add_argument("--pr-number", type=int, default=0, dest="pr_number")
    parser.add_argument(
        "--installation-id",
        type=int,
        default=0,
        dest="installation_id",
        help="GitHub App installation ID",
    )
    args = parser.parse_args()

    if args.prs and args.limit:
        parser.error("--prs and --limit are mutually exclusive")

    is_url = bool(args.pr_url)
    is_manual = bool(args.repo and args.package and args.old_version and args.new_version)
    is_batch = bool(args.repo and not is_manual)

    if is_url or is_manual:
        await _triage_single(args)
    elif is_batch:
        await _triage_batch(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
