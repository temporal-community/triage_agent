#!/usr/bin/env python3
"""
MCP stdio server for dependency-scout.

Exposes a single tool — check_dependency — that submits a PackageTriageWorkflow
to Temporal and returns the verdict. Wire it into Claude Code with:

    # .claude/settings.json
    {
      "mcpServers": {
        "dependency-scout": {
          "command": "uv",
          "args": ["run", "python", "-m", "mcp_server"]
        }
      }
    }

Results are automatically shared/deduped across callers: if another project already
checked the same version bump today, the cached verdict is returned immediately.

Requires a running Temporal worker:
    temporal server start-dev    # Terminal 1
    uv run python -m worker      # Terminal 2
"""

from __future__ import annotations

import os

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from temporalio.common import WorkflowIDReusePolicy
from temporalio.exceptions import WorkflowAlreadyStartedError

from helpers.temporal_client import connect
from models import TriageResult
from workflows.package_triage_workflow import PackageTriageWorkflow

load_dotenv()

mcp = FastMCP("dependency-scout")


@mcp.tool()
async def check_dependency(
    package: str,
    new_version: str,
    ecosystem: str = "pip",
    old_version: str = "",
) -> str:
    """Check whether a package version is safe to install or upgrade to.

    Returns a GREEN / YELLOW / RED verdict with reasoning and flags.
    Results are shared across callers — if another project already checked
    this exact version bump today, the cached verdict is returned immediately.

    Args:
        package: Package name (e.g. "requests", "@angular/core")
        new_version: Version to install or upgrade to (e.g. "2.32.0")
        ecosystem: Package ecosystem slug: pip, npm, gem, cargo, go, nuget, … (default: pip)
        old_version: Currently installed version — omit for fresh installs
    """
    client = await connect()
    task_queue = os.environ.get("TEMPORAL_TASK_QUEUE", "dependency-scout")
    workflow_id = f"triage-{ecosystem}-{package}-{new_version}"

    try:
        handle = await client.start_workflow(
            PackageTriageWorkflow.run,
            args=[ecosystem, package, old_version, new_version],
            id=workflow_id,
            task_queue=task_queue,
            id_reuse_policy=WorkflowIDReusePolicy.REJECT_DUPLICATE,
        )
    except WorkflowAlreadyStartedError:
        handle = client.get_workflow_handle_for(PackageTriageWorkflow.run, workflow_id)  # type: ignore[arg-type]

    result: TriageResult = await handle.result()
    v = result.verdict

    lines = [
        f"VERDICT: {v.classification.upper()}",
        f"Confidence: {v.confidence:.0%}",
        "",
        v.reasoning,
    ]
    if v.flags:
        lines += ["", f"Flags: {', '.join(v.flags)}"]
    if v.merge_recommendation:
        lines += ["", f"Recommendation: {v.merge_recommendation}"]

    return "\n".join(lines)


if __name__ == "__main__":
    mcp.run()
