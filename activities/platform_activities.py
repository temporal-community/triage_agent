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
from models import PRContext, PRFilesSignals, RepoConfig, Verdict
from helpers.config_provider import get_config_provider
from helpers.notification import get_notification_channels


@activity.defn(name="activities.platform.comment")
async def comment(pr: PRContext, verdict: Verdict) -> None:
    await get_notification_channels().send_verdict(pr, verdict)


@activity.defn(name="activities.platform.merge_pr")
async def merge_pr(pr: PRContext) -> None:
    await get_platform_client(pr).merge_pr(pr)


@activity.defn(name="activities.platform.close_pr")
async def close_pr(pr: PRContext, reason: str, ignore_bot: bool = False) -> None:
    await get_platform_client(pr).close_pr(pr, reason, ignore_bot)


@activity.defn(name="activities.platform.label")
async def label(pr: PRContext, label_name: str) -> None:
    await get_platform_client(pr).label(pr, label_name)


@activity.defn(name="activities.platform.request_review")
async def request_review(pr: PRContext, reviewers: list[str]) -> None:
    await get_platform_client(pr).request_review(pr, reviewers)


@activity.defn(name="activities.platform.check_pr_files")
async def check_pr_files(pr: PRContext) -> PRFilesSignals:
    return await get_platform_client(pr).check_pr_files(pr)


@activity.defn(name="activities.platform.fetch_repo_config")
async def fetch_repo_config(pr: PRContext) -> RepoConfig:
    config = await get_config_provider(pr.platform).fetch(pr)

    if os.environ.get("ENABLE_PR_ACTIONS", "false").lower() == "true":
        activity.logger.warning(
            "⚠️  ENABLE_PR_ACTIONS=true is set — overriding per-repo config to enable "
            "real PR actions (comments, merges) on ALL repos. This must never be set in production."
        )
        config = config.model_copy(update={"auto_merge_enabled": True})

    return config
