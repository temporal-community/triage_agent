"""
Generate Temporal workflow history fixtures for replay tests.

Run once to (re)generate committed JSON fixtures:
    uv run python tests/generate_fixtures.py

The resulting files in tests/fixtures/ are committed and consumed by
tests/test_workflow_replay.py to verify workflow determinism.
"""

import asyncio
import json
from pathlib import Path

from temporalio import activity
from temporalio.contrib.pydantic import pydantic_data_converter
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from models import (
    AttestationChecks,
    DepsDevChecks,
    DiffChecks,
    MaintainerChecks,
    OSVChecks,
    PRContext,
    PRFilesChecks,
    PyPIChecks,
    ReleaseAgeChecks,
    ReleaseChecks,
    RepoConfig,
    ScorecardChecks,
    SocketChecks,
    Verdict,
    VersionLineChecks,
)
from workflows.package_triage_workflow import PackageTriageWorkflow
from workflows.pr_action_workflow import PRActionWorkflow

FIXTURES_DIR = Path(__file__).parent / "fixtures"

_PR = PRContext(
    repo="example/repo",
    pr_number=42,
    pr_author="dependabot[bot]",
    installation_id=0,
    ecosystem="pip",
    package_name="requests",
    old_version="2.28.0",
    new_version="2.31.0",
)


# ---------------------------------------------------------------------------
# Mock activity factories — each call produces a fresh function so that
# multiple Workers in the same process don't share function objects.
# ---------------------------------------------------------------------------


def _pypi(is_major: bool = False):
    @activity.defn(name="activities.pypi_metadata.fetch")
    async def fetch(*_):
        return PyPIChecks(weekly_downloads=5_000_000, is_major_bump=is_major)

    return fetch


def _socket():
    @activity.defn(name="activities.socket.score")
    async def score(*_):
        return SocketChecks(socket_score=80, socket_alerts=[])

    return score


def _osv(has_cve: bool = False):
    @activity.defn(name="activities.osv.check")
    async def check(*_):
        return OSVChecks(osv_vulnerabilities=["CVE-2024-9999"] if has_cve else [])

    return check


def _diff():
    @activity.defn(name="activities.package_diff.compute")
    async def compute(*_):
        return DiffChecks(diff_summary="Minor doc changes.", diff_size_bytes=256)

    return compute


def _maintainer(changed: bool = False):
    @activity.defn(name="activities.maintainer.history")
    async def history(*_):
        return MaintainerChecks(maintainer_changed=changed)

    return history


def _release_age(hours: float = 720.0):
    @activity.defn(name="activities.release_age.check")
    async def check(*_):
        return ReleaseAgeChecks(release_age_hours=hours)

    return check


def _attestation(has_attestation: bool = True, publisher_repo: str = "psf/requests"):
    @activity.defn(name="activities.attestation.check")
    async def check(*_):
        return AttestationChecks(
            has_attestation=has_attestation,
            publisher_kind="GitHub" if has_attestation else None,
            publisher_repo=publisher_repo if has_attestation else None,
        )

    return check


def _release_notes():
    @activity.defn(name="activities.release_notes.check")
    async def check(*_):
        return ReleaseChecks(github_release_exists=True, release_is_automated=True)

    return check


def _classifier(classification: str):
    @activity.defn(name="activities.classifier.classify")
    async def classify(*_):
        return Verdict(
            classification=classification,
            confidence=0.95,
            reasoning=f"fixture:{classification}",
            flags=[],
            release_age_hours=720.0,
        )

    return classify


def _repo_config(config: RepoConfig):
    @activity.defn(name="activities.platform.fetch_repo_config")
    async def fetch_repo_config(*_):
        return config

    return fetch_repo_config


def _comment():
    @activity.defn(name="activities.platform.comment")
    async def comment(*_):
        pass

    return comment


def _merge():
    @activity.defn(name="activities.platform.merge_pr")
    async def merge_pr(*_):
        pass

    return merge_pr


def _review():
    @activity.defn(name="activities.platform.request_review")
    async def request_review(*_):
        pass

    return request_review


def _label():
    @activity.defn(name="activities.platform.label")
    async def label(*_):
        pass

    return label


def _close_pr():
    @activity.defn(name="activities.platform.close_pr")
    async def close_pr(*_):
        pass

    return close_pr


def _check_pr_files(unexpected: list[str] | None = None):
    @activity.defn(name="activities.platform.check_pr_files")
    async def check_pr_files(*_):
        return PRFilesChecks(unexpected_files=unexpected or [])

    return check_pr_files


def _version_lineage():
    @activity.defn(name="activities.version_lineage.check")
    async def check(*_):
        return VersionLineChecks()

    return check


def _depsdev():
    @activity.defn(name="activities.depsdev.fetch")
    async def fetch(*_):
        return DepsDevChecks()

    return fetch


def _scorecard():
    @activity.defn(name="activities.scorecard.fetch")
    async def fetch(*_):
        return ScorecardChecks()

    return fetch


# ---------------------------------------------------------------------------
# Scenarios: (fixture_name, verdict_class, repo_config, human_signal | None)
# ---------------------------------------------------------------------------

SCENARIOS = [
    (
        "green_automerge",
        "green",
        RepoConfig(auto_merge_enabled=True, auto_merge_classifications=["green"]),
        None,
    ),
    (
        "yellow_human_approved",
        "yellow",
        RepoConfig(reviewers=["alice"]),
        "approve",
    ),
    (
        "yellow_human_rejected",
        "yellow",
        RepoConfig(reviewers=["alice"]),
        "reject",
    ),
    (
        "red_blocked",
        "red",
        RepoConfig(block_classifications=["red"]),
        None,
    ),
    (
        "observe_only",
        "green",
        RepoConfig(),
        None,
    ),
]


async def _run_scenario(
    env: WorkflowEnvironment,
    name: str,
    classification: str,
    config: RepoConfig,
    human_signal: str | None,
) -> None:
    acts = [
        _pypi(),
        _socket(),
        _osv(),
        _diff(),
        _maintainer(),
        _release_age(),
        _attestation(),
        _release_notes(),
        _version_lineage(),
        _depsdev(),
        _scorecard(),
        _classifier(classification),
        _repo_config(config),
        _comment(),
        _merge(),
        _review(),
        _label(),
        _close_pr(),
        _check_pr_files(),
    ]
    async with Worker(
        env.client,
        task_queue="gen-fixtures",
        workflows=[PRActionWorkflow, PackageTriageWorkflow],
        activities=acts,
    ):
        # For human-review scenarios, embed the signal atomically in the workflow
        # start event using start_signal. This puts the decision in the workflow
        # history before the first task runs, so wait_condition is satisfied
        # immediately and the 7-day timer is never scheduled.
        start_kwargs: dict = {}
        if human_signal is not None:
            start_kwargs = {
                "start_signal": "submit_decision",
                "start_signal_args": [human_signal, "alice"],
            }
        handle = await env.client.start_workflow(
            PRActionWorkflow.run,
            _PR,
            id=f"fix-{name}",
            task_queue="gen-fixtures",
            **start_kwargs,
        )
        await handle.result()

        history = await handle.fetch_history()
        path = FIXTURES_DIR / f"pr_action_{name}.json"
        path.write_text(
            json.dumps(
                {"workflowId": f"fix-{name}", "history": json.loads(history.to_json())},
                indent=2,
            )
        )
        print(f"  wrote {path.name}")


async def main() -> None:
    FIXTURES_DIR.mkdir(exist_ok=True)
    for name, classification, config, human_signal in SCENARIOS:
        print(f"generating {name}...")
        # Each scenario gets its own isolated environment so workflow IDs
        # and task queues never collide.
        async with await WorkflowEnvironment.start_time_skipping(
            data_converter=pydantic_data_converter
        ) as env:
            await _run_scenario(env, name, classification, config, human_signal)
    print("done — fixtures written to tests/fixtures/")


if __name__ == "__main__":
    asyncio.run(main())
