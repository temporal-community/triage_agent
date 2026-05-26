"""
CLI to manually trigger a triage run. Useful for testing without a webhook.

Usage:
    uv run python -m start_workflow https://github.com/owner/repo/pull/123
    uv run python -m start_workflow --repo owner/repo --pr-number 123
    uv run python -m start_workflow --repo owner/repo --package requests \\
        --old-version 2.31.0 --new-version 2.32.0
"""

import argparse
import asyncio
import os
import re
import sys

import httpx
from dotenv import load_dotenv
from temporalio.client import Client, TLSConfig
from temporalio.contrib.pydantic import pydantic_data_converter

from helpers.pr_parser import parse_pr
from models import PRContext
from workflows.pr_action_workflow import PRActionWorkflow

load_dotenv()

_GITHUB_PR_RE = re.compile(r"github\.com/([^/]+/[^/]+)/pull/(\d+)")


async def _fetch_pr(url: str) -> tuple[str, str, str, str, int]:
    """Return (ecosystem, package, old_version, new_version, pr_number) from a GitHub PR URL."""
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
        sys.exit(f"PR not found: {url}  (private repo? set GITHUB_TOKEN in .env)")
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
            "Use --package, --old-version, --new-version to specify manually."
        )
    return parsed.ecosystem, parsed.package, parsed.old_version, parsed.new_version, int(pr_num)


async def main() -> None:
    parser = argparse.ArgumentParser(description="Manually trigger dependency triage")
    parser.add_argument("pr_url", nargs="?", help="GitHub PR URL (derives all other args)")
    parser.add_argument("--repo", help="owner/repo (required without a PR URL)")
    parser.add_argument("--pr-number", type=int, default=0, dest="pr_number")
    parser.add_argument("--package")
    parser.add_argument("--old-version", dest="old_version")
    parser.add_argument("--new-version", dest="new_version")
    parser.add_argument("--ecosystem", default="pip")
    parser.add_argument("--installation-id", type=int, default=0, dest="installation_id")
    args = parser.parse_args()

    if args.pr_url:
        m = _GITHUB_PR_RE.search(args.pr_url)
        if not m:
            sys.exit(f"Unrecognized PR URL: {args.pr_url!r}")
        repo = m.group(1)
        ecosystem, package, old_version, new_version, pr_number = await _fetch_pr(args.pr_url)
    elif (
        args.repo and args.pr_number and not (args.package or args.old_version or args.new_version)
    ):
        # repo + pr-number only: fetch from GitHub
        url = f"https://github.com/{args.repo}/pull/{args.pr_number}"
        ecosystem, package, old_version, new_version, pr_number = await _fetch_pr(url)
        repo = args.repo
    elif args.repo and args.package and args.old_version and args.new_version:
        repo = args.repo
        ecosystem = args.ecosystem
        package = args.package
        old_version = args.old_version
        new_version = args.new_version
        pr_number = args.pr_number
    else:
        parser.print_help()
        sys.exit(1)

    tls: TLSConfig | bool = False
    cert_path = os.environ.get("TEMPORAL_TLS_CERT")
    key_path = os.environ.get("TEMPORAL_TLS_KEY")
    if cert_path and key_path:
        tls = TLSConfig(
            client_cert=open(cert_path, "rb").read(),
            client_private_key=open(key_path, "rb").read(),
        )

    client = await Client.connect(
        os.environ.get("TEMPORAL_ADDRESS", "localhost:7233"),
        namespace=os.environ.get("TEMPORAL_NAMESPACE", "default"),
        tls=tls,
        data_converter=pydantic_data_converter,
    )

    pr = PRContext(
        repo=repo,
        pr_number=pr_number,
        pr_author="dependabot[bot]",
        installation_id=args.installation_id,
        ecosystem=ecosystem,
        package_name=package,
        old_version=old_version,
        new_version=new_version,
    )

    workflow_id = f"pr-action-{repo.replace('/', '-')}-{pr_number}"
    has_anthropic = bool(os.environ.get("ANTHROPIC_API_KEY"))
    has_github = bool(os.environ.get("GITHUB_TOKEN"))
    classifier_mode = (
        "LLM (claude-sonnet-4-6)" if has_anthropic else "rule-based (no ANTHROPIC_API_KEY)"
    )
    github_mode = "real GitHub API" if has_github else "dry-run (no GITHUB_TOKEN)"
    print(f"Triaging {repo}#{pr_number}  {package} {old_version} → {new_version}  ({ecosystem})")
    print(f"  classifier : {classifier_mode}")
    print(f"  github     : {github_mode}")
    print()

    handle = await client.start_workflow(
        PRActionWorkflow.run,
        pr,
        id=workflow_id,
        task_queue=os.environ.get("TEMPORAL_TASK_QUEUE", "dependency-triage"),
    )
    print(f"Started workflow: {handle.id}")
    ui_base = os.environ.get("TEMPORAL_UI_BASE_URL", "http://localhost:8233")
    ns = os.environ.get("TEMPORAL_NAMESPACE", "default")
    print(f"Temporal UI: {ui_base}/namespaces/{ns}/workflows/{handle.id}")

    result = await handle.result()
    print(f"Result: {result}")


if __name__ == "__main__":
    asyncio.run(main())
