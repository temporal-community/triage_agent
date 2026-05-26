"""
PlatformClient Protocol and factory.

A PlatformClient handles all PR-management operations for a specific platform
(GitHub, GitLab, …).  Add a new platform by:
  1. Implementing PlatformClient in a module (platforms/{name}.py or a plugin package)
  2. Exposing a factory function with signature (pr: PRContext) -> PlatformClient
  3. Registering it under the dependency_scout.platforms entry point group:
       [project.entry-points."dependency_scout.platforms"]
       myplatform = "my_package.platform:create_client"

Built-in platforms (github, gitlab) are also registered as entry points so the
factory is a uniform lookup; the if/elif fallback handles dev environments where
the package isn't installed in editable mode.
"""

from __future__ import annotations

import os
from typing import Protocol

from models import PackageChecks, PRContext, PRFilesChecks, ActionsUsageChecks, Verdict


class PlatformClient(Protocol):
    async def comment(
        self, pr: PRContext, verdict: Verdict, signals: PackageChecks | None = None
    ) -> str | None: ...
    async def merge_pr(self, pr: PRContext) -> None: ...
    async def close_pr(self, pr: PRContext, reason: str, ignore_bot: bool = False) -> None: ...
    async def label(self, pr: PRContext, label_name: str) -> None: ...
    async def request_review(self, pr: PRContext, reviewers: list[str]) -> None: ...
    async def check_pr_files(self, pr: PRContext) -> PRFilesChecks: ...
    async def fetch_actions_usage(self, pr: PRContext) -> ActionsUsageChecks: ...


def get_platform_client(pr: PRContext) -> PlatformClient:
    # Check entry points first so third-party platforms (and overrides of built-ins) work.
    try:
        from importlib.metadata import entry_points

        for ep in entry_points(group="dependency_scout.platforms"):
            if ep.name == pr.platform:
                factory = ep.load()
                return factory(pr)
    except Exception:  # noqa: BLE001
        pass

    # Built-in fallbacks for dev environments where the package isn't installed.
    if pr.platform == "github":
        from platforms.github import GitHubPlatformClient

        return GitHubPlatformClient(installation_id=pr.installation_id)
    if pr.platform == "gitlab":
        from platforms.gitlab import GitLabPlatformClient

        base_url = os.environ.get("GITLAB_BASE_URL", "https://gitlab.com")
        return GitLabPlatformClient(base_url=base_url)
    raise ValueError(f"Unknown platform: {pr.platform!r}")
