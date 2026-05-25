"""
ConfigProvider protocol — abstracts where triage configuration comes from.

Default routing is by platform:
  github  → GitHubConfigProvider reads .github/dependency-scout.yml via GitHub API
  gitlab  → GitLabConfigProvider reads .gitlab/dependency-scout.yml via GitLab Files API

Override for all platforms via TRIAGE_CONFIG_PROVIDER=env (reads TRIAGE_CONFIG_* vars).
"""

from __future__ import annotations

import os
from typing import Any, Protocol

from models import PRContext, RepoConfig


class ConfigProvider(Protocol):
    """Returns the triage configuration for a given PR's repository."""

    async def fetch(self, pr: PRContext) -> RepoConfig: ...


class GitHubConfigProvider:
    """Reads .github/dependency-scout.yml from the target repo via GitHub Contents API."""

    async def fetch(self, pr: PRContext) -> RepoConfig:
        import base64

        import httpx
        import yaml
        from temporalio import activity
        from temporalio.exceptions import ApplicationError

        url = f"https://api.github.com/repos/{pr.repo}/contents/.github/dependency-scout.yml"
        headers = {"Accept": "application/vnd.github+json"}

        if token := os.environ.get("GITHUB_TOKEN"):
            headers["Authorization"] = f"Bearer {token}"
        elif pr.installation_id:
            from helpers.github_app import get_installation_token

            token = await get_installation_token(pr.installation_id)
            headers["Authorization"] = f"Bearer {token}"

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(url, headers=headers)

        if resp.status_code == 404:
            activity.logger.info(
                f"No .github/dependency-scout.yml in {pr.repo} — "
                "using observe-only defaults (comment on every PR, no auto-merge, no review requests, no blocking)"
            )
            return RepoConfig()

        if resp.status_code == 401:
            raise ApplicationError("GitHub auth failed fetching repo config", non_retryable=True)

        resp.raise_for_status()
        content_b64 = resp.json()["content"].replace("\n", "")
        raw = base64.b64decode(content_b64).decode("utf-8")
        data = yaml.safe_load(raw) or {}
        known = {k: v for k, v in data.items() if k in RepoConfig.model_fields}
        config = RepoConfig(**known)
        activity.logger.info(f"Loaded .github/dependency-scout.yml from {pr.repo}: {config}")
        return config


class EnvConfigProvider:
    """Reads per-repo triage config from environment variables.

    Useful for GitLab/Gitea platforms and for testing without GitHub API calls.
    All vars are optional; omitted keys use RepoConfig defaults.

    TRIAGE_CONFIG_AUTO_MERGE=true
    TRIAGE_CONFIG_REVIEWERS=alice,bob
    TRIAGE_CONFIG_MIN_RELEASE_AGE_HOURS=48
    TRIAGE_CONFIG_AUTO_MERGE_CLASSIFICATIONS=green
    TRIAGE_CONFIG_BLOCK_CLASSIFICATIONS=red
    TRIAGE_CONFIG_MAX_NEW_DEPENDENCIES=5
    """

    async def fetch(self, pr: PRContext) -> RepoConfig:
        def _bool(key: str) -> bool | None:
            v = os.environ.get(key)
            return v.lower() in ("1", "true", "yes") if v is not None else None

        def _list(key: str) -> list[str] | None:
            v = os.environ.get(key)
            return [x.strip() for x in v.split(",") if x.strip()] if v is not None else None

        def _int(key: str) -> int | None:
            v = os.environ.get(key)
            try:
                return int(v) if v is not None else None
            except ValueError:
                return None

        auto_merge = _bool("TRIAGE_CONFIG_AUTO_MERGE")
        reviewers = _list("TRIAGE_CONFIG_REVIEWERS")
        min_age = _int("TRIAGE_CONFIG_MIN_RELEASE_AGE_HOURS")
        auto_merge_cls = _list("TRIAGE_CONFIG_AUTO_MERGE_CLASSIFICATIONS")
        block_cls = _list("TRIAGE_CONFIG_BLOCK_CLASSIFICATIONS")
        max_new_deps = _int("TRIAGE_CONFIG_MAX_NEW_DEPENDENCIES")
        kwargs: dict[str, Any] = {}
        if auto_merge is not None:
            kwargs["auto_merge_enabled"] = auto_merge
        if reviewers is not None:
            kwargs["reviewers"] = reviewers
        if min_age is not None:
            kwargs["min_release_age_hours"] = min_age
        if auto_merge_cls is not None:
            kwargs["auto_merge_classifications"] = auto_merge_cls
        if block_cls is not None:
            kwargs["block_classifications"] = block_cls
        if max_new_deps is not None:
            kwargs["max_new_dependencies"] = max_new_deps
        return RepoConfig(**kwargs)


class GitLabConfigProvider:
    """Reads .gitlab/dependency-scout.yml from the target repo via GitLab Files API."""

    async def fetch(self, pr: PRContext) -> RepoConfig:
        from urllib.parse import quote

        import httpx
        import yaml
        from temporalio import activity
        from temporalio.exceptions import ApplicationError

        base_url = os.environ.get("GITLAB_BASE_URL", "https://gitlab.com").rstrip("/")
        encoded_path = quote(pr.repo, safe="")
        file_path = quote(".gitlab/dependency-scout.yml", safe="")
        url = f"{base_url}/api/v4/projects/{encoded_path}/repository/files/{file_path}/raw"

        headers: dict = {}
        if token := os.environ.get("GITLAB_TOKEN"):
            headers["Authorization"] = f"Bearer {token}"

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(url, headers=headers, params={"ref": "HEAD"})

        if resp.status_code == 404:
            activity.logger.info(
                f"No .gitlab/dependency-scout.yml in {pr.repo} — using observe-only defaults"
            )
            return RepoConfig()

        if resp.status_code == 401:
            raise ApplicationError("GitLab auth failed fetching repo config", non_retryable=True)

        resp.raise_for_status()
        data = yaml.safe_load(resp.text) or {}
        known = {k: v for k, v in data.items() if k in RepoConfig.model_fields}
        config = RepoConfig(**known)
        activity.logger.info(f"Loaded .gitlab/dependency-scout.yml from {pr.repo}: {config}")
        return config


def get_config_provider(platform: str = "github") -> ConfigProvider:
    """Return the active ConfigProvider. TRIAGE_CONFIG_PROVIDER=env overrides platform routing."""
    name = os.environ.get("TRIAGE_CONFIG_PROVIDER", "").lower()
    if name == "env":
        return EnvConfigProvider()
    if platform == "gitlab":
        return GitLabConfigProvider()
    return GitHubConfigProvider()
