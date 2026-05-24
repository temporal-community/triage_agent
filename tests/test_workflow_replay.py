"""
Temporal workflow replay tests.

These tests load committed JSON history fixtures from tests/fixtures/ and
replay them through the Replayer to verify that the workflow code is
deterministic. A replay failure means a non-deterministic change was
introduced — the kind of bug that corrupts live workflow state mid-execution.

To regenerate fixtures after an intentional workflow change:
    uv run python tests/generate_fixtures.py
"""

import json
from pathlib import Path

import pytest
from temporalio.client import WorkflowHistory
from temporalio.contrib.pydantic import pydantic_data_converter
from temporalio.worker import Replayer

from workflows.package_triage_workflow import PackageTriageWorkflow
from workflows.pr_action_workflow import PRActionWorkflow

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _load(name: str) -> WorkflowHistory:
    path = FIXTURES_DIR / f"pr_action_{name}.json"
    data = json.loads(path.read_text())
    return WorkflowHistory.from_json(data["workflowId"], data["history"])


@pytest.fixture(scope="module")
def replayer() -> Replayer:
    return Replayer(
        workflows=[PRActionWorkflow, PackageTriageWorkflow],
        data_converter=pydantic_data_converter,
    )


# ---------------------------------------------------------------------------
# One test per scenario — each replays independently
# ---------------------------------------------------------------------------


async def test_replay_green_automerge(replayer: Replayer) -> None:
    """GREEN verdict + auto-merge config → workflow completes as 'auto-merged'."""
    await replayer.replay_workflow(_load("green_automerge"))


async def test_replay_yellow_human_approved(replayer: Replayer) -> None:
    """YELLOW verdict + reviewers config → 7-day wait timed out (no live server in fixture gen)."""
    await replayer.replay_workflow(_load("yellow_human_approved"))


async def test_replay_yellow_human_rejected(replayer: Replayer) -> None:
    """YELLOW verdict + reviewers config → 7-day wait timed out (no live server in fixture gen)."""
    await replayer.replay_workflow(_load("yellow_human_rejected"))


async def test_replay_red_blocked(replayer: Replayer) -> None:
    """RED verdict + block config → labelled and blocked."""
    await replayer.replay_workflow(_load("red_blocked"))


async def test_replay_observe_only(replayer: Replayer) -> None:
    """No config file → observe-only: comment posted, nothing else done."""
    await replayer.replay_workflow(_load("observe_only"))
