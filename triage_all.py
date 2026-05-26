#!/usr/bin/env python3
"""
Triage all open Dependabot / Renovate PRs in a repo via the Temporal worker.

Usage:
    uv run python triage_all.py --repo owner/repo
    uv run python triage_all.py --repo owner/repo --limit 10

Requires a running Temporal worker:
    temporal server start-dev    # Terminal 1
    uv run python -m worker      # Terminal 2

Set GITHUB_TOKEN in .env to post real comments; without it, runs in dry-run mode.
Set ANTHROPIC_API_KEY for LLM classification; without it, rule-based fallback is used.
"""

import argparse
import asyncio
import os
import sys

import httpx
from dotenv import load_dotenv
from temporalio.client import Client, TLSConfig
from temporalio.contrib.pydantic import pydantic_data_converter

from helpers.pr_parser import parse_pr, ParsedPR
from models import PRContext
from workflows.pr_action_workflow import PRActionWorkflow

load_dotenv()

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


def _verdict_from_result(result: str) -> str:
    """Extract green/yellow/red from a PRActionWorkflow return string."""
    if "green" in result or result == "auto-merged" or result == "human-approved-merged":
        return "green"
    if "red" in result:
        return "red"
    return "yellow"


def _color_verdict(verdict: str) -> str:
    emoji = {"green": "🟢", "yellow": "🟡", "red": "🔴"}[verdict]
    color = {"green": _G, "yellow": _Y, "red": _R}[verdict]
    return f"{emoji} {color}{_B}{verdict.upper()}{_RST}"


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
                sys.exit(f"Repo not found: {repo!r}  (private? set GITHUB_TOKEN in .env)")
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


async def _triage_one(
    client: Client, repo: str, pr_data: dict, parsed: ParsedPR
) -> tuple[dict, ParsedPR, str]:
    pr = PRContext(
        repo=repo,
        pr_number=pr_data["number"],
        pr_author=pr_data["user"]["login"],
        ecosystem=parsed.ecosystem,
        package_name=parsed.package,
        old_version=parsed.old_version,
        new_version=parsed.new_version,
    )
    workflow_id = f"pr-action-{repo.replace('/', '-')}-{pr_data['number']}"
    handle = await client.start_workflow(
        PRActionWorkflow.run,
        pr,
        id=workflow_id,
        task_queue=os.environ.get("TEMPORAL_TASK_QUEUE", "dependency-triage"),
    )
    result: str = await handle.result()
    return pr_data, parsed, result


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="Triage all open Dependabot/Renovate PRs in a repo."
    )
    parser.add_argument("--repo", required=True, help="owner/repo")
    parser.add_argument("--limit", type=int, help="Cap number of PRs to triage")
    args = parser.parse_args()

    token = os.environ.get("GITHUB_TOKEN")
    has_github = bool(token)
    has_llm = bool(
        os.environ.get("ANTHROPIC_API_KEY")
        or os.environ.get("OPENAI_API_KEY")
        or os.environ.get("OLLAMA_HOST")
        or os.environ.get("CLASSIFIER")
    )

    if has_llm:
        from classifiers import get_classifier

        clf_name = type(get_classifier()).__name__.replace("Classifier", "")
    else:
        clf_name = None

    print(_dim(f"Fetching open Dependabot/Renovate PRs for {args.repo} ..."))
    all_prs = await _list_dependabot_prs(args.repo, token)

    # Parse PR titles; skip anything that doesn't look like a dep bump.
    parseable: list[tuple[dict, ParsedPR]] = []
    skipped: list[dict] = []
    for pr in all_prs:
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

    cap_note = (
        f"  {_dim(f'(showing first {args.limit} of {len(parseable) + len(parseable) - args.limit})')}"
        if args.limit
        else ""
    )
    print(f"\nFound {_B}{len(parseable)}{_RST} PRs to triage:{cap_note}\n")

    # Pre-flight list
    pkg_w = max(len(p.package) for _, p in parseable)
    for pr, parsed in parseable:
        print(
            f"  #{pr['number']:<5} {parsed.package:<{pkg_w}}  "
            f"{parsed.old_version} → {parsed.new_version}  "
            f"{_dim(f'({parsed.ecosystem})')}"
        )

    if skipped:
        print(f"\n  {_dim(f'Skipping {len(skipped)} PR(s) with unparseable titles.')}")

    # Environment summary
    github_desc = (
        _g("will post real comments on PRs")
        if has_github
        else f"{_C}dry-run — add GITHUB_TOKEN to .env to post real comments{_RST}"
    )
    clf_desc = (
        _g(f"{clf_name} — LLM-powered verdict")
        if clf_name
        else f"{_C}rule-based fallback — add ANTHROPIC_API_KEY to .env for LLM analysis{_RST}"
    )
    print(f"\n  github     {github_desc}")
    print(f"  classifier {clf_desc}")
    print(_dim("\n" + "─" * 60 + "\n"))

    client = await _connect()

    tasks = [
        asyncio.create_task(_triage_one(client, args.repo, pr, parsed)) for pr, parsed in parseable
    ]

    counts: dict[str, int] = {"green": 0, "yellow": 0, "red": 0}
    result_w = pkg_w

    print(f"Triaging {len(tasks)} PRs in parallel ...\n")
    ui_base = os.environ.get("TEMPORAL_UI_BASE_URL", "http://localhost:8233")
    ns = os.environ.get("TEMPORAL_NAMESPACE", "default")

    for future in asyncio.as_completed(tasks):
        try:
            pr_data, parsed, result = await future
        except Exception as exc:
            print(f"  {_y('!')}  workflow error: {exc}")
            continue

        verdict = _verdict_from_result(result)
        counts[verdict] += 1
        pr_url = f"https://github.com/{args.repo}/pull/{pr_data['number']}"
        wf_id = f"pr-action-{args.repo.replace('/', '-')}-{pr_data['number']}"
        print(
            f"  {_color_verdict(verdict)}  "
            f"#{pr_data['number']:<5} {parsed.package:<{result_w}}  "
            f"{parsed.old_version} → {parsed.new_version}  "
            f"{_dim(pr_url)}"
        )
        print(f"  {'':>{6 + result_w + 20}} {_dim(f'{ui_base}/namespaces/{ns}/workflows/{wf_id}')}")

    total = sum(counts.values())
    print(_dim("\n" + "─" * 60))
    g, y, r = counts["green"], counts["yellow"], counts["red"]
    print(
        f"  {_B}{total} done{_RST}  ·  "
        f"{_g(f'{g} green')}  ·  "
        f"{_y(f'{y} yellow')}  ·  "
        f"{_r(f'{r} red')}"
    )
    print(_dim("─" * 60))


if __name__ == "__main__":
    asyncio.run(main())
