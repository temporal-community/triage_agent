"""
PlatformClient Protocol and factory.

A PlatformClient handles all PR-management operations for a specific platform
(GitHub, GitLab, …).  Add a new platform by:
  1. Implementing PlatformClient in activities/platform/{name}.py
  2. Adding a branch to get_platform_client() below
"""

from __future__ import annotations

import os
from typing import Protocol

from activities.models import PRContext, PRFilesSignals, Verdict


class PlatformClient(Protocol):
    async def comment(self, pr: PRContext, verdict: Verdict) -> None: ...
    async def merge_pr(self, pr: PRContext) -> None: ...
    async def close_pr(self, pr: PRContext, reason: str, ignore_bot: bool = False) -> None: ...
    async def label(self, pr: PRContext, label_name: str) -> None: ...
    async def request_review(self, pr: PRContext, reviewers: list[str]) -> None: ...
    async def check_pr_files(self, pr: PRContext) -> PRFilesSignals: ...


def get_platform_client(pr: PRContext) -> PlatformClient:
    if pr.platform == "github":
        from activities.platform.github import GitHubPlatformClient

        return GitHubPlatformClient(installation_id=pr.installation_id)
    if pr.platform == "gitlab":
        from activities.platform.gitlab import GitLabPlatformClient

        base_url = os.environ.get("GITLAB_BASE_URL", "https://gitlab.com")
        return GitLabPlatformClient(base_url=base_url)
    raise ValueError(f"Unknown platform: {pr.platform!r}")
