import base64
import os

import httpx
import yaml
from temporalio import activity
from temporalio.exceptions import ApplicationError

from activities.models import PRContext, RepoConfig


@activity.defn(name="activities.repo_config.fetch")
async def fetch(pr: PRContext) -> RepoConfig:
    config = await _fetch_from_github(pr)

    if os.environ.get("ENABLE_PR_ACTIONS", "false").lower() == "true":
        # Intentional footgun guard: log loudly so this never silently slips into prod.
        activity.logger.warning(
            "⚠️  ENABLE_PR_ACTIONS=true is set — overriding per-repo config to enable "
            "real PR actions (comments, merges) on ALL repos. This must never be set in production."
        )
        config = config.model_copy(update={"auto_merge_enabled": True})

    return config


async def _fetch_from_github(pr: PRContext) -> RepoConfig:
    url = f"https://api.github.com/repos/{pr.repo}/contents/.github/triage-agent.yml"
    headers = {"Accept": "application/vnd.github+json"}

    # Auth priority: PAT (local dev) → GitHub App installation token (production)
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
            f"No .github/triage-agent.yml in {pr.repo} — "
            "using observe-only defaults (comment on every PR, no auto-merge, no review requests, no blocking)"
        )
        return RepoConfig()

    if resp.status_code == 401:
        raise ApplicationError("GitHub auth failed fetching repo config", non_retryable=True)

    resp.raise_for_status()

    content_b64 = resp.json()["content"].replace("\n", "")
    raw = base64.b64decode(content_b64).decode("utf-8")
    data = yaml.safe_load(raw) or {}

    # Only pass fields that RepoConfig actually knows about
    known = {k: v for k, v in data.items() if k in RepoConfig.model_fields}
    config = RepoConfig(**known)
    activity.logger.info(f"Loaded .github/triage-agent.yml from {pr.repo}: {config}")
    return config
