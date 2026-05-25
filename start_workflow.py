"""
CLI to manually trigger a triage run. Useful for testing without a webhook.

Usage:
    uv run python -m start_workflow \\
        --repo owner/repo \\
        --package requests \\
        --old-version 2.31.0 \\
        --new-version 2.32.0
"""

import argparse
import asyncio
import os
from dotenv import load_dotenv
from temporalio.client import Client, TLSConfig
from temporalio.contrib.pydantic import pydantic_data_converter

from models import PRContext
from workflows.pr_action_workflow import PRActionWorkflow

load_dotenv()


async def main() -> None:
    parser = argparse.ArgumentParser(description="Manually trigger dependency triage")
    parser.add_argument("--repo", required=True, help="owner/repo")
    parser.add_argument("--package", required=True)
    parser.add_argument("--old-version", required=True, dest="old_version")
    parser.add_argument("--new-version", required=True, dest="new_version")
    parser.add_argument("--pr-number", type=int, default=1, dest="pr_number")
    parser.add_argument("--installation-id", type=int, default=0, dest="installation_id")
    parser.add_argument("--ecosystem", default="pip", choices=["pip", "npm"])
    args = parser.parse_args()

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
        repo=args.repo,
        pr_number=args.pr_number,
        pr_author="dependabot[bot]",
        installation_id=args.installation_id,
        ecosystem=args.ecosystem,
        package_name=args.package,
        old_version=args.old_version,
        new_version=args.new_version,
    )

    workflow_id = f"pr-action-{args.repo.replace('/', '-')}-{args.pr_number}"
    # Show which mode we're running in
    has_anthropic = bool(os.environ.get("ANTHROPIC_API_KEY"))
    has_github = bool(os.environ.get("GITHUB_TOKEN"))
    classifier_mode = (
        "LLM (claude-sonnet-4-6)" if has_anthropic else "rule-based (no ANTHROPIC_API_KEY)"
    )
    github_mode = "real GitHub API" if has_github else "dry-run (no GITHUB_TOKEN)"
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
