import base64

import httpx
import pytest
import respx
from temporalio.testing import ActivityEnvironment

from activities.platform_activities import fetch_repo_config as fetch
from activities.models import PRContext, RepoConfig
from helpers.config_provider import EnvConfigProvider

GITHUB_CONTENTS_URL = (
    "https://api.github.com/repos/owner/repo/contents/.github/dependency-scout.yml"
)

PR = PRContext(
    repo="owner/repo",
    pr_number=1,
    pr_author="dependabot[bot]",
    installation_id=0,
    ecosystem="pip",
    package_name="requests",
    old_version="2.31.0",
    new_version="2.32.0",
)


def _contents_response(yaml_text: str) -> dict:
    return {"content": base64.b64encode(yaml_text.encode()).decode() + "\n"}


@respx.mock
async def test_missing_config_returns_defaults():
    respx.get(GITHUB_CONTENTS_URL).mock(return_value=httpx.Response(404))
    env = ActivityEnvironment()
    result = await env.run(fetch, PR)
    assert result == RepoConfig()
    assert result.auto_merge_enabled is False
    assert result.reviewers == []


@respx.mock
async def test_config_loaded_and_parsed():
    yaml_text = "auto_merge_enabled: true\nreviewers: [alice, bob]\nmin_release_age_hours: 48\n"
    respx.get(GITHUB_CONTENTS_URL).mock(
        return_value=httpx.Response(200, json=_contents_response(yaml_text))
    )
    env = ActivityEnvironment()
    result = await env.run(fetch, PR)
    assert result.auto_merge_enabled is True
    assert result.reviewers == ["alice", "bob"]
    assert result.min_release_age_hours == 48


@respx.mock
async def test_unknown_fields_ignored():
    yaml_text = "auto_merge_enabled: true\nunknown_field: whatever\n"
    respx.get(GITHUB_CONTENTS_URL).mock(
        return_value=httpx.Response(200, json=_contents_response(yaml_text))
    )
    env = ActivityEnvironment()
    result = await env.run(fetch, PR)
    assert result.auto_merge_enabled is True


@respx.mock
async def test_empty_config_returns_defaults():
    respx.get(GITHUB_CONTENTS_URL).mock(
        return_value=httpx.Response(200, json=_contents_response(""))
    )
    env = ActivityEnvironment()
    result = await env.run(fetch, PR)
    assert result == RepoConfig()


@respx.mock
async def test_force_auto_merge_override(monkeypatch):
    monkeypatch.setenv("ENABLE_PR_ACTIONS", "true")
    respx.get(GITHUB_CONTENTS_URL).mock(return_value=httpx.Response(404))
    env = ActivityEnvironment()
    result = await env.run(fetch, PR)
    assert result.auto_merge_enabled is True


@respx.mock
async def test_pat_sent_in_auth_header(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghs_testpat")
    route = respx.get(GITHUB_CONTENTS_URL).mock(return_value=httpx.Response(404))
    env = ActivityEnvironment()
    await env.run(fetch, PR)
    assert route.calls[0].request.headers["Authorization"] == "Bearer ghs_testpat"


@respx.mock
async def test_401_raises_non_retryable(monkeypatch):
    from temporalio.exceptions import ApplicationError

    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    respx.get(GITHUB_CONTENTS_URL).mock(return_value=httpx.Response(401))
    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(fetch, PR)
    assert exc_info.value.non_retryable is True


@respx.mock
async def test_github_app_token_used_when_installation_id_set(monkeypatch):
    """When no PAT is set and installation_id is non-zero, auth via GitHub App token."""
    from unittest.mock import AsyncMock, patch

    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    app_pr = PR.model_copy(update={"installation_id": 99999})
    route = respx.get(GITHUB_CONTENTS_URL).mock(return_value=httpx.Response(404))

    with patch(
        "helpers.github_app.get_installation_token", new=AsyncMock(return_value="app_token_xyz")
    ):
        env = ActivityEnvironment()
        await env.run(fetch, app_pr)

    assert route.calls[0].request.headers["Authorization"] == "Bearer app_token_xyz"


# ---------------------------------------------------------------------------
# EnvConfigProvider
# ---------------------------------------------------------------------------


async def test_env_provider_defaults_when_no_vars_set(monkeypatch):
    for key in [
        "TRIAGE_CONFIG_AUTO_MERGE",
        "TRIAGE_CONFIG_REVIEWERS",
        "TRIAGE_CONFIG_MIN_RELEASE_AGE_HOURS",
        "TRIAGE_CONFIG_BLOCK_CLASSIFICATIONS",
        "TRIAGE_CONFIG_AUTO_MERGE_CLASSIFICATIONS",
        "TRIAGE_CONFIG_MAX_NEW_DEPENDENCIES",
    ]:
        monkeypatch.delenv(key, raising=False)
    result = await EnvConfigProvider().fetch(PR)
    assert result == RepoConfig()


async def test_env_provider_reads_auto_merge(monkeypatch):
    monkeypatch.setenv("TRIAGE_CONFIG_AUTO_MERGE", "true")
    result = await EnvConfigProvider().fetch(PR)
    assert result.auto_merge_enabled is True


async def test_env_provider_reads_reviewers(monkeypatch):
    monkeypatch.setenv("TRIAGE_CONFIG_REVIEWERS", "alice, bob")
    result = await EnvConfigProvider().fetch(PR)
    assert result.reviewers == ["alice", "bob"]


async def test_env_provider_reads_min_age(monkeypatch):
    monkeypatch.setenv("TRIAGE_CONFIG_MIN_RELEASE_AGE_HOURS", "48")
    result = await EnvConfigProvider().fetch(PR)
    assert result.min_release_age_hours == 48


async def test_env_provider_selected_via_env_var(monkeypatch):
    monkeypatch.setenv("TRIAGE_CONFIG_PROVIDER", "env")
    monkeypatch.setenv("TRIAGE_CONFIG_AUTO_MERGE", "true")
    env = ActivityEnvironment()
    result = await env.run(fetch, PR)
    assert result.auto_merge_enabled is True
