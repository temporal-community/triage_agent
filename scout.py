#!/usr/bin/env python3
"""
Check whether a package is safe to install or upgrade, using Temporal-backed supply chain analysis.

Fresh install check:
    scout check requests 2.32.0

Upgrade check:
    scout check requests 2.32.0 --from 2.31.0

Different ecosystem:
    scout check @angular/core 18.0.0 --ecosystem npm

Exit codes: 0 = green, 1 = yellow, 2 = red (scriptable / CI-friendly)

Requires a running Temporal worker:
    temporal server start-dev    # Terminal 1
    uv run python -m worker      # Terminal 2
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys

from dotenv import load_dotenv
from temporalio.common import WorkflowIDReusePolicy
from temporalio.exceptions import WorkflowAlreadyStartedError

from helpers.display import _bold, _clf_name, _color_verdict, _dim, _g, _info, _merge_rec_label
from helpers.temporal_client import connect
from models import TriageResult
from workflows.package_triage_workflow import PackageTriageWorkflow

load_dotenv()


async def _check(package: str, new_version: str, ecosystem: str, old_version: str) -> int:
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
    task_queue = os.environ.get("TEMPORAL_TASK_QUEUE", "dependency-scout")
    workflow_id = f"triage-{ecosystem}-{package}-{new_version}"

    print(_dim("  Submitting to Temporal…"))
    try:
        handle = await client.start_workflow(
            PackageTriageWorkflow.run,
            args=[ecosystem, package, old_version, new_version],
            id=workflow_id,
            task_queue=task_queue,
            id_reuse_policy=WorkflowIDReusePolicy.REJECT_DUPLICATE,
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


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="scout",
        description="Vet a dependency before installing or updating it.",
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

    args = parser.parse_args()

    if args.command == "check":
        exit_code = asyncio.run(
            _check(args.package, args.version, args.ecosystem, args.old_version)
        )
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
