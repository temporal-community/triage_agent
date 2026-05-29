#!/usr/bin/env python3
"""
dependency-scout — vet dependencies and triage Dependabot/Renovate PRs.

Check a single package version:
    dependency-scout check requests 2.32.0
    dependency-scout check requests 2.32.0 --from 2.31.0
    dependency-scout check @angular/core 18.0.0 --ecosystem npm

Triage a single PR by URL:
    dependency-scout triage https://github.com/owner/repo/pull/123

Triage all open Dependabot/Renovate PRs in a repo:
    dependency-scout triage --repo owner/repo

Triage specific PRs:
    dependency-scout triage --repo owner/repo --prs 12,33,64

Triage first N PRs:
    dependency-scout triage --repo owner/repo --limit 5

Add --dry-run to any triage command to skip posting comments or taking actions.

Exit codes (dependency-scout check): 0 = green, 1 = yellow, 2 = red (CI-friendly)

Requires a running Temporal worker:
    temporal server start-dev    # Terminal 1
    uv run python -m worker      # Terminal 2
"""

from __future__ import annotations

import argparse
import asyncio
import os
import re
import sys
from datetime import datetime

import httpx
from dotenv import load_dotenv
from temporalio.client import Client
from temporalio.common import WorkflowIDReusePolicy
from temporalio.exceptions import WorkflowAlreadyStartedError

from helpers.display import (
    _B,
    _RST,
    _bold,
    _clf_name,
    _color_verdict,
    _dim,
    _g,
    _info,
    _merge_rec_label,
    _r,
    _y,
)
from helpers.pr_parser import ParsedPR, parse_pr
from helpers.temporal_client import connect
from models import PRContext, TriageResult
from workflows.package_triage_workflow import PackageTriageWorkflow
from workflows.pr_action_workflow import PRActionWorkflow

load_dotenv()

_GITHUB_PR_RE = re.compile(r"github\.com/([^/]+/[^/]+)/pull/(\d+)")


# ---------------------------------------------------------------------------
# scout check
# ---------------------------------------------------------------------------


async def _check(
    package: str, new_version: str, ecosystem: str, old_version: str, force: bool = False
) -> int:
    from_part = f"{_dim(old_version + ' → ')}" if old_version else ""
    print(f"\n  {_bold(package)}  {from_part}{new_version}  [{ecosystem}]")

    clf = _clf_name()
    clf_desc = (
        _g(f"{clf} — LLM-powered verdict")
        if clf
        else _info("rule-based fallback — add ANTHROPIC_API_KEY to .env for LLM analysis")
    )
    print(f"  classifier  {clf_desc}\n")

    client = await connect()
    task_queue = os.environ.get("TEMPORAL_TASK_QUEUE", "default")
    date_key = datetime.now().strftime("%Y-%m-%d")
    workflow_id = f"triage-{ecosystem}-{package}-{new_version}-{date_key}"

    print(_dim("  Submitting to Temporal…"))
    if force:
        try:
            await client.get_workflow_handle(workflow_id).terminate(reason="forced re-triage")
            print(_dim("  (terminated prior cached result — starting fresh)"))
        except Exception:
            pass
    try:
        handle = await client.start_workflow(
            PackageTriageWorkflow.run,
            args=[ecosystem, package, old_version, new_version],
            id=workflow_id,
            task_queue=task_queue,
            id_reuse_policy=WorkflowIDReusePolicy.ALLOW_DUPLICATE
            if force
            else WorkflowIDReusePolicy.REJECT_DUPLICATE,
        )
    except WorkflowAlreadyStartedError:
        print(_dim("  (attaching to existing triage run — cached result)"))
        handle = client.get_workflow_handle_for(PackageTriageWorkflow.run, workflow_id)  # type: ignore[arg-type]

    result: TriageResult = await handle.result()
    v = result.verdict

    print(f"\n{_color_verdict(v.classification)}\n")
    print(f"  {v.reasoning}")
    if v.flags:
        print(f"\n  Flags: {', '.join(v.flags)}")
    rec = _merge_rec_label(v.merge_recommendation)
    if rec:
        print(f"\n{rec}")
    print(f"\n  {_dim(f'Confidence: {v.confidence:.0%}')}\n")

    return {"green": 0, "yellow": 1, "red": 2}[v.classification]


# ---------------------------------------------------------------------------
# scout triage — shared helpers
# ---------------------------------------------------------------------------


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


def _unwrap_cause(exc: Exception) -> str:
    """Walk Temporal's WorkflowFailureError → ActivityError → ApplicationError chain to get the real message."""
    cause: Exception = exc
    while hasattr(cause, "cause") and getattr(cause, "cause", None) is not None:
        cause = cause.cause  # type: ignore[assignment]
    return str(cause)


def _parse_result(result: str) -> tuple[str, str | None, str | None]:
    """Return (status, comment_url, merge_recommendation) from workflow result string."""
    parts = result.split("||")
    status = parts[0]
    comment_url = parts[1] if len(parts) > 1 and parts[1] else None
    merge_rec = parts[2] if len(parts) > 2 and parts[2] in ("merge", "hold") else None
    return status, comment_url, merge_rec


def _verdict_from_result(result: str) -> str:
    status = result.split("||")[0]
    if "green" in status or status in ("auto-merged", "human-approved-merged"):
        return "green"
    if "red" in status:
        return "red"
    return "yellow"


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
# scout triage — single PR
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

    client = await connect()
    workflow_id = f"pr-action-{repo.replace('/', '-')}-{pr_number}"
    handle = await client.start_workflow(
        PRActionWorkflow.run,
        pr,
        id=workflow_id,
        task_queue=os.environ.get("TEMPORAL_TASK_QUEUE", "default"),
    )

    ui_base = os.environ.get("TEMPORAL_UI_BASE_URL", "http://localhost:8233")
    ns = os.environ.get("TEMPORAL_NAMESPACE", "default")
    print(f"  Workflow: {handle.id}")
    wf_url = f"{ui_base}/namespaces/{ns}/workflows/{handle.id}"
    print(f"  Temporal: {wf_url}")
    print()

    result = await handle.result()
    result_str, comment_url, merge_rec = _parse_result(result)
    verdict = _verdict_from_result(result)
    mr_label = _merge_rec_label(merge_rec)
    print(f"  {_color_verdict(verdict)}{mr_label}  {_dim(result_str)}")
    if comment_url:
        print(f"  Comment:  {comment_url}")
    elif not args.dry_run and has_github and pr_number:
        print(f"  PR:       https://github.com/{repo}/pull/{pr_number}")
    print()


# ---------------------------------------------------------------------------
# scout triage — batch
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
        task_queue=os.environ.get("TEMPORAL_TASK_QUEUE", "default"),
    )
    return pr_data, parsed, await handle.result()


async def _cleanup_orphaned_triage_workflows(client: Client) -> None:
    """Terminate all running PackageTriageWorkflow and PRActionWorkflow instances."""
    terminated = 0
    for wf_type in ("PackageTriageWorkflow", "PRActionWorkflow"):
        try:
            async for wf in client.list_workflows(
                f"WorkflowType='{wf_type}' AND ExecutionStatus='Running'"
            ):
                try:
                    await client.get_workflow_handle(wf.id, run_id=wf.run_id).terminate(
                        reason="triage re-run cleanup"
                    )
                    terminated += 1
                except Exception:
                    pass
        except Exception:
            pass
    if terminated:
        print(_dim(f"  Cleaned up {terminated} orphaned workflow(s) from a previous run.\n"))


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

    client = await connect()
    await _cleanup_orphaned_triage_workflows(client)
    tasks = [
        asyncio.create_task(_triage_one(client, args.repo, pr, parsed, dry_run=args.dry_run))
        for pr, parsed in parseable
    ]

    ui_base = os.environ.get("TEMPORAL_UI_BASE_URL", "http://localhost:8233")
    ns = os.environ.get("TEMPORAL_NAMESPACE", "default")
    repo_slug = args.repo.replace("/", "-")

    print(f"Triaging {len(tasks)} PR(s) in parallel ...\n")

    completed: list[tuple] = []
    failed: list[str] = []
    _verdict_rank = {"red": 0, "yellow": 1, "green": 2}

    for future in asyncio.as_completed(tasks):
        try:
            pr_data, parsed, result = await future
            result_str, comment_url, merge_rec = _parse_result(result)
            verdict = _verdict_from_result(result)
            completed.append((pr_data, parsed, verdict, result_str, comment_url, merge_rec))
            mr_label = _merge_rec_label(merge_rec)
            print(
                f"  {_color_verdict(verdict)}{mr_label}  "
                f"#{pr_data['number']:<5}  {parsed.package:<{pkg_w}}  "
                f"{parsed.old_version} → {parsed.new_version}"
            )
        except Exception as exc:
            msg = _unwrap_cause(exc)
            failed.append(msg)
            print(f"  {_r(_B + '✗' + _RST)}  {_r(msg)}")

    groups: dict[tuple, list] = {}
    for entry in completed:
        pr_data, parsed, verdict, result_str, comment_url, merge_rec = entry
        key = (parsed.package, parsed.old_version, parsed.new_version)
        groups.setdefault(key, []).append(entry)

    def _group_sort_key(item: tuple) -> tuple:
        (pkg, old_v, new_v), entries = item
        worst = min(_verdict_rank.get(e[2], 9) for e in entries)
        return (worst, pkg)

    ver_w = max(len(f"{old_v} → {new_v}") for pkg, old_v, new_v in groups) if groups else 0
    print(_dim("\n" + "─" * 60 + "\n"))
    counts: dict[str, int] = {"green": 0, "yellow": 0, "red": 0}
    for (pkg, old_v, new_v), entries in sorted(groups.items(), key=_group_sort_key):
        verdict = min(entries, key=lambda e: _verdict_rank.get(e[2], 9))[2]
        counts[verdict] += len(entries)
        pr_nums = sorted(e[0]["number"] for e in entries)
        pr_label = "  ".join(f"#{n}" for n in pr_nums)
        ver_str = f"{old_v} → {new_v}"
        print(f"  {_color_verdict(verdict)}  {pkg:<{pkg_w}}  {ver_str:<{ver_w}}  {_dim(pr_label)}")
        rep = entries[0]
        rep_pr_data, _, _, _, comment_url, _ = rep
        wf_id = f"pr-action-{repo_slug}-{rep_pr_data['number']}"
        wf_url = f"{ui_base}/namespaces/{ns}/workflows/{wf_id}"
        extra = f"  {_dim(f'(+{len(entries) - 1} more)')}" if len(entries) > 1 else ""
        if comment_url:
            print(f"        Comment:  {comment_url}{extra}")
        else:
            pr_url = f"https://github.com/{args.repo}/pull/{rep_pr_data['number']}"
            print(f"        PR:       {pr_url}{extra}")
        print(f"        Workflow: {wf_url}{extra}")

    total = sum(counts.values())
    g, y, r = counts["green"], counts["yellow"], counts["red"]
    unique = len(groups)
    pr_note = f"  {_dim(f'({total} PRs across {unique} unique bumps)')}" if unique < total else ""
    summary = (
        f"  {_bold(f'{unique} done')}  ·  "
        f"{_g(f'{g} green')}  ·  "
        f"{_y(f'{y} yellow')}  ·  "
        f"{_r(f'{r} red')}"
        f"{pr_note}"
    )
    if failed:
        summary += f"  ·  {_r(_bold(f'{len(failed)} failed'))}"
    print(_dim("\n" + "─" * 60))
    print(summary)
    print(_dim("─" * 60))


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def _add_triage_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("pr_url", nargs="?", help="GitHub PR URL (single-PR mode)")
    p.add_argument("--repo", metavar="OWNER/REPO", help="repository to triage")
    p.add_argument("--prs", metavar="N,N,...", help="comma-separated PR numbers (requires --repo)")
    p.add_argument("--limit", type=int, metavar="N", help="max PRs to triage (requires --repo)")
    p.add_argument(
        "--dry-run",
        action="store_true",
        dest="dry_run",
        help="triage without posting comments or taking any actions",
    )
    p.add_argument("--package", help="package name (manual override)")
    p.add_argument("--old-version", dest="old_version", help="old version (manual override)")
    p.add_argument("--new-version", dest="new_version", help="new version (manual override)")
    p.add_argument("--ecosystem", default="pip", help="ecosystem (default: pip)")
    p.add_argument("--pr-number", type=int, default=0, dest="pr_number")
    p.add_argument(
        "--installation-id",
        type=int,
        default=0,
        dest="installation_id",
        help="GitHub App installation ID",
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="default",
        description="Vet dependencies and triage Dependabot/Renovate PRs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  dependency-scout check requests 2.32.0\n"
            "  dependency-scout check requests 2.32.0 --from 2.31.0\n"
            "  dependency-scout triage https://github.com/owner/repo/pull/123\n"
            "  dependency-scout triage --repo owner/repo\n"
            "  dependency-scout triage --repo owner/repo --prs 12,33,64\n"
            "  dependency-scout triage --repo owner/repo --limit 5 --dry-run"
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    check_p = sub.add_parser("check", help="Check a single package version.")
    check_p.add_argument("package", help="Package name (e.g. requests, @angular/core)")
    check_p.add_argument("version", help="Version to install or upgrade to (e.g. 2.32.0)")
    check_p.add_argument(
        "--from",
        dest="old_version",
        default="",
        metavar="VERSION",
        help="Currently installed version — omit for fresh installs",
    )
    check_p.add_argument(
        "--ecosystem",
        "-e",
        default="pip",
        help="Ecosystem slug: pip, npm, gem, cargo, go, nuget, … (default: pip)",
    )
    check_p.add_argument(
        "--force",
        action="store_true",
        help="Ignore cached result and run a fresh triage",
    )

    triage_p = sub.add_parser(
        "triage",
        help="Triage Dependabot/Renovate PRs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  dependency-scout triage https://github.com/owner/repo/pull/123\n"
            "  dependency-scout triage --repo owner/repo\n"
            "  dependency-scout triage --repo owner/repo --prs 12,33,64\n"
            "  dependency-scout triage --repo owner/repo --limit 5 --dry-run"
        ),
    )
    _add_triage_args(triage_p)

    args = parser.parse_args()

    if args.command == "check":
        exit_code = asyncio.run(
            _check(args.package, args.version, args.ecosystem, args.old_version, args.force)
        )
        sys.exit(exit_code)

    if args.command == "triage":
        if args.prs and args.limit:
            triage_p.error("--prs and --limit are mutually exclusive")

        is_url = bool(args.pr_url)
        is_manual = bool(args.repo and args.package and args.old_version and args.new_version)
        is_batch = bool(args.repo and not is_manual)

        if is_url or is_manual:
            asyncio.run(_triage_single(args))
        elif is_batch:
            asyncio.run(_triage_batch(args))
        else:
            triage_p.print_help()
            sys.exit(1)


if __name__ == "__main__":
    main()
