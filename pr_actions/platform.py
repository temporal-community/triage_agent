"""
Temporal activity definitions for platform PR-management operations.

These are thin wrappers around PlatformClient that give each operation a
stable, platform-neutral activity name used by workflow code.  The actual
platform (GitHub, GitLab, …) is determined at runtime from pr.platform.
"""

from __future__ import annotations

import os

from temporalio import activity

from platforms import get_platform_client
from models import (
    PRContext,
    PackageChecks,
    PRFilesChecks,
    ActionsUsageChecks,
    RepoConfig,
    TriageResult,
    Verdict,
)
from helpers.config_provider import get_config_provider
from helpers.notification import get_notification_channels
from helpers.temporal_client import connect as temporal_connect


@activity.defn(name="activities.platform.comment")
async def comment(pr: PRContext, verdict: Verdict, signals: PackageChecks | None = None) -> str:
    """Post the triage verdict as a comment on the PR using all configured notification channels (e.g. GitHub/GitLab comment, Slack). Returns the comment URL, or empty string if dry-run/unavailable."""
    if pr.dry_run:
        activity.logger.info(
            f"[dry-run] would post {verdict.classification.upper()} comment on "
            f"{pr.repo}#{pr.pr_number} — skipping (pass --no-dry-run or unset --dry-run to post)"
        )
        return ""
    url = await get_notification_channels().send_verdict(pr, verdict, signals)
    return url or ""


@activity.defn(name="activities.platform.merge_pr")
async def merge_pr(pr: PRContext) -> None:
    """Merge the pull request via the GitHub or GitLab API."""
    await get_platform_client(pr).merge_pr(pr)


@activity.defn(name="activities.platform.close_pr")
async def close_pr(pr: PRContext, reason: str, ignore_bot: bool = False) -> None:
    """Close the pull request without merging, posting the given reason as a comment via the GitHub or GitLab API."""
    await get_platform_client(pr).close_pr(pr, reason, ignore_bot)


@activity.defn(name="activities.platform.label")
async def label(pr: PRContext, label_name: str) -> None:
    """Apply a label to the pull request via the GitHub or GitLab API."""
    await get_platform_client(pr).label(pr, label_name)


@activity.defn(name="activities.platform.request_review")
async def request_review(pr: PRContext, reviewers: list[str]) -> None:
    """Request a review from the specified users on the pull request via the GitHub or GitLab API."""
    await get_platform_client(pr).request_review(pr, reviewers)


@activity.defn(name="activities.platform.check_pr_files")
async def check_pr_files(pr: PRContext) -> PRFilesChecks:
    """Fetch the list of files changed in the PR from the GitHub or GitLab API and return basic metadata about them (e.g. whether any lock files were modified)."""
    return await get_platform_client(pr).check_pr_files(pr)


@activity.defn(name="activities.platform.check_actions_usage")
async def check_actions_usage(pr: PRContext) -> ActionsUsageChecks:
    """For github_actions bumps, fetch .github/workflows/ from the target repo and extract how the bumped action is used (which inputs are configured). Returns empty for non-Actions ecosystems."""
    return await get_platform_client(pr).fetch_actions_usage(pr)


@activity.defn(name="activities.platform.await_triage_result")
async def await_triage_result(workflow_id: str) -> TriageResult:
    """Attach to an already-running PackageTriageWorkflow and return its result.

    Called when execute_child_workflow fails with 'already started' — a sibling
    PRActionWorkflow (another PR in the same monorepo bumping the same package)
    got to this triage first. We wait for its result instead of running a duplicate.
    """
    client = await temporal_connect()
    handle = client.get_workflow_handle(workflow_id)
    result = await handle.result()
    return TriageResult.model_validate(result)


@activity.defn(name="activities.platform.fetch_repo_config")
async def fetch_repo_config(pr: PRContext) -> RepoConfig:
    """Read the ``dependency-scout.yml`` configuration file from the target repository and return the parsed settings (auto-merge rules, reviewer lists, etc.)."""
    config = await get_config_provider(pr.platform).fetch(pr)

    if os.environ.get("ENABLE_PR_ACTIONS", "false").lower() == "true":
        activity.logger.warning(
            "⚠️  ENABLE_PR_ACTIONS=true is set — overriding per-repo config to enable "
            "real PR actions (comments, merges) on ALL repos. This must never be set in production."
        )
        config = config.model_copy(update={"auto_merge_enabled": True})

    return config
