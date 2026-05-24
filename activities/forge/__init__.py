"""
ForgeClient Protocol and factory.

A ForgeClient handles all PR-management operations for a specific forge
(GitHub, GitLab, …).  Add a new forge by:
  1. Implementing ForgeClient in activities/forge/{name}.py
  2. Adding a branch to get_forge_client() below
"""
from __future__ import annotations

import os
from typing import Protocol

from activities.models import PRContext, PRFilesSignals, Verdict


class ForgeClient(Protocol):
    async def comment(self, pr: PRContext, verdict: Verdict) -> None: ...
    async def merge_pr(self, pr: PRContext) -> None: ...
    async def close_pr(self, pr: PRContext, reason: str, ignore_bot: bool = False) -> None: ...
    async def label(self, pr: PRContext, label_name: str) -> None: ...
    async def request_review(self, pr: PRContext, reviewers: list[str]) -> None: ...
    async def check_pr_files(self, pr: PRContext) -> PRFilesSignals: ...
    async def fetch_repo_config(self, pr: PRContext) -> str | None: ...


def get_forge_client(pr: PRContext) -> ForgeClient:
    if pr.forge == "github":
        from activities.forge.github import GitHubForgeClient
        return GitHubForgeClient(installation_id=pr.installation_id)
    if pr.forge == "gitlab":
        from activities.forge.gitlab import GitLabForgeClient
        base_url = os.environ.get("GITLAB_BASE_URL", "https://gitlab.com")
        return GitLabForgeClient(base_url=base_url)
    raise ValueError(f"Unknown forge: {pr.forge!r}")
