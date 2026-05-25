"""
Tests for activities/platform/gitlab.py (GitLabPlatformClient).

All non-dry-run tests set GITLAB_TOKEN to bypass dry-run mode.
HTTP calls are mocked with respx.
"""

from __future__ import annotations

import json
from urllib.parse import quote

import httpx
import pytest
import respx
from temporalio.exceptions import ApplicationError
from temporalio.testing import ActivityEnvironment

from platforms.gitlab import GitLabPlatformClient, _is_ci_infra_file
from models import PRContext, PRFilesChecks as PRFilesSignals, Verdict

REPO = "owner/repo"
PR_NUM = 42
ENCODED_REPO = quote(REPO, safe="")
BASE_URL = f"https://gitlab.com/api/v4/projects/{ENCODED_REPO}"
USERS_URL = "https://gitlab.com/api/v4/users"


@pytest.fixture
def client():
    return GitLabPlatformClient()


@pytest.fixture
def pr():
    return PRContext(
        repo=REPO,
        pr_number=PR_NUM,
        pr_author="renovate[bot]",
        installation_id=None,
        platform="gitlab",
        ecosystem="pip",
        package_name="requests",
        old_version="2.31.0",
        new_version="2.32.0",
        head_sha="abc123",
    )


@pytest.fixture
def verdict():
    return Verdict(
        classification="green",
        confidence=0.95,
        reasoning="Routine patch bump.",
        flags=[],
    )


@pytest.fixture
def with_token(monkeypatch):
    monkeypatch.setenv("GITLAB_TOKEN", "glpat_test")


@pytest.fixture
def dry_run(monkeypatch):
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)


# ---------------------------------------------------------------------------
# _dry_run
# ---------------------------------------------------------------------------


def test_dry_run_true_when_no_token(monkeypatch):
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)
    assert GitLabPlatformClient()._dry_run() is True


def test_dry_run_false_with_token(monkeypatch):
    monkeypatch.setenv("GITLAB_TOKEN", "glpat_test")
    assert GitLabPlatformClient()._dry_run() is False


# ---------------------------------------------------------------------------
# comment
# ---------------------------------------------------------------------------


@respx.mock
async def test_comment_dry_run_makes_no_http_call(client, pr, verdict, dry_run):
    env = ActivityEnvironment()
    await env.run(client.comment, pr, verdict)


@respx.mock
async def test_comment_posts_to_correct_url(client, pr, verdict, with_token):
    route = respx.post(f"{BASE_URL}/merge_requests/{PR_NUM}/notes").mock(
        return_value=httpx.Response(201, json={})
    )
    env = ActivityEnvironment()
    await env.run(client.comment, pr, verdict)
    assert route.called


@respx.mock
async def test_comment_body_contains_verdict_badge(client, pr, verdict, with_token):
    route = respx.post(f"{BASE_URL}/merge_requests/{PR_NUM}/notes").mock(
        return_value=httpx.Response(201, json={})
    )
    env = ActivityEnvironment()
    await env.run(client.comment, pr, verdict)
    body = route.calls[0].request.content.decode()
    assert "GREEN" in body


@respx.mock
async def test_comment_401_raises_non_retryable(client, pr, verdict, with_token):
    respx.post(f"{BASE_URL}/merge_requests/{PR_NUM}/notes").mock(return_value=httpx.Response(401))
    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(client.comment, pr, verdict)
    assert exc_info.value.non_retryable is True


# ---------------------------------------------------------------------------
# merge_pr
# ---------------------------------------------------------------------------


@respx.mock
async def test_merge_pr_dry_run_makes_no_http_call(client, pr, dry_run):
    env = ActivityEnvironment()
    await env.run(client.merge_pr, pr)


@respx.mock
async def test_merge_pr_state_not_opened_raises_non_retryable(client, pr, with_token):
    respx.get(f"{BASE_URL}/merge_requests/{PR_NUM}").mock(
        return_value=httpx.Response(200, json={"state": "merged", "sha": "abc123"})
    )
    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(client.merge_pr, pr)
    assert exc_info.value.non_retryable is True
    assert "merged" in str(exc_info.value)


@respx.mock
async def test_merge_pr_sha_mismatch_raises_non_retryable(client, pr, with_token):
    respx.get(f"{BASE_URL}/merge_requests/{PR_NUM}").mock(
        return_value=httpx.Response(200, json={"state": "opened", "sha": "different_sha"})
    )
    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(client.merge_pr, pr)
    assert exc_info.value.non_retryable is True
    assert "SHA" in str(exc_info.value)


@respx.mock
async def test_merge_pr_skips_sha_check_when_head_sha_empty(client, pr, with_token):
    pr.head_sha = ""
    respx.get(f"{BASE_URL}/merge_requests/{PR_NUM}").mock(
        return_value=httpx.Response(200, json={"state": "opened", "sha": "anything"})
    )
    respx.put(f"{BASE_URL}/merge_requests/{PR_NUM}/merge").mock(
        return_value=httpx.Response(200, json={})
    )
    env = ActivityEnvironment()
    await env.run(client.merge_pr, pr)


@respx.mock
async def test_merge_pr_405_is_retryable(client, pr, with_token):
    respx.get(f"{BASE_URL}/merge_requests/{PR_NUM}").mock(
        return_value=httpx.Response(200, json={"state": "opened", "sha": "abc123"})
    )
    respx.put(f"{BASE_URL}/merge_requests/{PR_NUM}/merge").mock(
        return_value=httpx.Response(405, json={"message": "pipeline running"})
    )
    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(client.merge_pr, pr)
    assert exc_info.value.non_retryable is False


@respx.mock
async def test_merge_pr_422_is_non_retryable(client, pr, with_token):
    respx.get(f"{BASE_URL}/merge_requests/{PR_NUM}").mock(
        return_value=httpx.Response(200, json={"state": "opened", "sha": "abc123"})
    )
    respx.put(f"{BASE_URL}/merge_requests/{PR_NUM}/merge").mock(
        return_value=httpx.Response(422, json={"message": "merge conflict"})
    )
    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(client.merge_pr, pr)
    assert exc_info.value.non_retryable is True
    assert "merge conflict" in str(exc_info.value)


@respx.mock
async def test_merge_pr_success_uses_squash(client, pr, with_token):
    respx.get(f"{BASE_URL}/merge_requests/{PR_NUM}").mock(
        return_value=httpx.Response(200, json={"state": "opened", "sha": "abc123"})
    )
    merge_route = respx.put(f"{BASE_URL}/merge_requests/{PR_NUM}/merge").mock(
        return_value=httpx.Response(200, json={})
    )
    env = ActivityEnvironment()
    await env.run(client.merge_pr, pr)
    body = json.loads(merge_route.calls[0].request.content)
    assert body["squash"] is True
    assert body["sha"] == "abc123"


# ---------------------------------------------------------------------------
# close_pr
# ---------------------------------------------------------------------------


@respx.mock
async def test_close_pr_dry_run_makes_no_http_call(client, pr, dry_run):
    env = ActivityEnvironment()
    await env.run(client.close_pr, pr, "Suspicious release.")


@respx.mock
async def test_close_pr_posts_comment_then_closes_mr(client, pr, with_token):
    comment_route = respx.post(f"{BASE_URL}/merge_requests/{PR_NUM}/notes").mock(
        return_value=httpx.Response(201, json={})
    )
    close_route = respx.put(f"{BASE_URL}/merge_requests/{PR_NUM}").mock(
        return_value=httpx.Response(200, json={})
    )
    env = ActivityEnvironment()
    await env.run(client.close_pr, pr, "Suspicious release.")
    assert comment_route.called
    assert close_route.called
    close_body = json.loads(close_route.calls[0].request.content)
    assert close_body["state_event"] == "close"


@respx.mock
async def test_close_pr_422_raises_non_retryable(client, pr, with_token):
    respx.post(f"{BASE_URL}/merge_requests/{PR_NUM}/notes").mock(
        return_value=httpx.Response(201, json={})
    )
    respx.put(f"{BASE_URL}/merge_requests/{PR_NUM}").mock(
        return_value=httpx.Response(422, json={"message": "already closed"})
    )
    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(client.close_pr, pr, "Blocked.")
    assert exc_info.value.non_retryable is True
    assert "already closed" in str(exc_info.value)


# ---------------------------------------------------------------------------
# request_review
# ---------------------------------------------------------------------------


@respx.mock
async def test_request_review_dry_run_makes_no_http_call(client, pr, dry_run):
    env = ActivityEnvironment()
    await env.run(client.request_review, pr, ["alice", "bob"])


@respx.mock
async def test_request_review_resolves_usernames_and_updates_mr(client, pr, with_token):
    respx.get(USERS_URL).mock(
        side_effect=[
            httpx.Response(200, json=[{"id": 101}]),
            httpx.Response(200, json=[{"id": 202}]),
        ]
    )
    update_route = respx.put(f"{BASE_URL}/merge_requests/{PR_NUM}").mock(
        return_value=httpx.Response(200, json={})
    )
    env = ActivityEnvironment()
    await env.run(client.request_review, pr, ["alice", "bob"])
    body = json.loads(update_route.calls[0].request.content)
    assert set(body["reviewer_ids"]) == {101, 202}


@respx.mock
async def test_request_review_skips_unknown_users(client, pr, with_token):
    respx.get(USERS_URL).mock(
        side_effect=[
            httpx.Response(200, json=[]),  # nobody → no match
            httpx.Response(200, json=[{"id": 202}]),  # bob → found
        ]
    )
    update_route = respx.put(f"{BASE_URL}/merge_requests/{PR_NUM}").mock(
        return_value=httpx.Response(200, json={})
    )
    env = ActivityEnvironment()
    await env.run(client.request_review, pr, ["nobody", "bob"])
    body = json.loads(update_route.calls[0].request.content)
    assert body["reviewer_ids"] == [202]


@respx.mock
async def test_request_review_no_valid_users_skips_update(client, pr, with_token):
    respx.get(USERS_URL).mock(return_value=httpx.Response(200, json=[]))
    env = ActivityEnvironment()
    await env.run(client.request_review, pr, ["nobody"])
    # No PUT should be made (reviewer_ids would be empty)


# ---------------------------------------------------------------------------
# label
# ---------------------------------------------------------------------------


@respx.mock
async def test_label_dry_run_makes_no_http_call(client, pr, dry_run):
    env = ActivityEnvironment()
    await env.run(client.label, pr, "supply-chain-suspicious")


@respx.mock
async def test_label_puts_add_labels(client, pr, with_token):
    route = respx.put(f"{BASE_URL}/merge_requests/{PR_NUM}").mock(
        return_value=httpx.Response(200, json={})
    )
    env = ActivityEnvironment()
    await env.run(client.label, pr, "supply-chain-suspicious")
    body = json.loads(route.calls[0].request.content)
    assert body["add_labels"] == "supply-chain-suspicious"


# ---------------------------------------------------------------------------
# check_pr_files
# ---------------------------------------------------------------------------


@respx.mock
async def test_check_pr_files_dry_run_returns_empty(client, pr, dry_run):
    env = ActivityEnvironment()
    result = await env.run(client.check_pr_files, pr)
    assert result == PRFilesSignals()
    assert result.unexpected_files == []


@respx.mock
async def test_check_pr_files_clean_mr_returns_empty(client, pr, with_token):
    respx.get(f"{BASE_URL}/merge_requests/{PR_NUM}/changes").mock(
        return_value=httpx.Response(
            200,
            json={
                "changes": [
                    {"new_path": "requirements.txt"},
                    {"new_path": "requirements-dev.txt"},
                ]
            },
        )
    )
    env = ActivityEnvironment()
    result = await env.run(client.check_pr_files, pr)
    assert result.unexpected_files == []


@respx.mock
async def test_check_pr_files_detects_ci_yaml(client, pr, with_token):
    respx.get(f"{BASE_URL}/merge_requests/{PR_NUM}/changes").mock(
        return_value=httpx.Response(
            200,
            json={
                "changes": [
                    {"new_path": "requirements.txt"},
                    {"new_path": ".gitlab-ci.yml"},
                ]
            },
        )
    )
    env = ActivityEnvironment()
    result = await env.run(client.check_pr_files, pr)
    assert result.unexpected_files == [".gitlab-ci.yml"]


@respx.mock
async def test_check_pr_files_detects_multiple_suspicious_files(client, pr, with_token):
    respx.get(f"{BASE_URL}/merge_requests/{PR_NUM}/changes").mock(
        return_value=httpx.Response(
            200,
            json={
                "changes": [
                    {"new_path": "package.json"},
                    {"new_path": "Dockerfile"},
                    {"new_path": "deploy.sh"},
                ]
            },
        )
    )
    env = ActivityEnvironment()
    result = await env.run(client.check_pr_files, pr)
    assert set(result.unexpected_files) == {"Dockerfile", "deploy.sh"}


@respx.mock
async def test_check_pr_files_401_raises_non_retryable(client, pr, with_token):
    respx.get(f"{BASE_URL}/merge_requests/{PR_NUM}/changes").mock(return_value=httpx.Response(401))
    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(client.check_pr_files, pr)
    assert exc_info.value.non_retryable is True


# ---------------------------------------------------------------------------
# _is_ci_infra_file
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        ".gitlab-ci.yml",
        ".gitlab-ci.yaml",
        ".gitlab/pipeline.yml",
        ".github/workflows/ci.yml",
        ".circleci/config.yml",
        ".buildkite/pipeline.yml",
        "Jenkinsfile",
        ".travis.yml",
        "Makefile",
        "makefile",
        "GNUmakefile",
        "deploy.sh",
        "build.bash",
        "install.ps1",
        "run.bat",
        "run.cmd",
        "Dockerfile",
        "Dockerfile.prod",
        "dockerfile",
        "docker-compose.yml",
        ".dockerignore",
    ],
)
def test_is_ci_infra_file_detects_suspicious(path):
    assert _is_ci_infra_file(path) is True


@pytest.mark.parametrize(
    "path",
    [
        "requirements.txt",
        "package.json",
        "Gemfile",
        "pyproject.toml",
        "src/main.py",
        "lib/utils.js",
        "README.md",
    ],
)
def test_is_ci_infra_file_passes_dep_files(path):
    assert _is_ci_infra_file(path) is False


# ---------------------------------------------------------------------------
# get_platform_client factory — GitLab branch + unknown platform
# ---------------------------------------------------------------------------


def test_get_platform_client_returns_gitlab_client(pr, monkeypatch):
    monkeypatch.setenv("GITLAB_BASE_URL", "https://gitlab.example.com")
    from platforms import get_platform_client

    c = get_platform_client(pr)
    assert isinstance(c, GitLabPlatformClient)
    assert c._base_url == "https://gitlab.example.com"


def test_get_platform_client_unknown_platform_raises():
    from unittest.mock import MagicMock
    from platforms import get_platform_client

    unknown_pr = MagicMock()
    unknown_pr.platform = "bitbucket"
    with pytest.raises(ValueError, match="Unknown platform"):
        get_platform_client(unknown_pr)


# ---------------------------------------------------------------------------
# platform_activities wrappers — smoke tests for GitLab PRContext
# ---------------------------------------------------------------------------


@respx.mock
async def test_platform_activity_comment_delegates(pr, verdict, with_token):
    respx.post(f"{BASE_URL}/merge_requests/{PR_NUM}/notes").mock(
        return_value=httpx.Response(201, json={})
    )
    from activities.platform_activities import comment

    env = ActivityEnvironment()
    await env.run(comment, pr, verdict)


@respx.mock
async def test_platform_activity_merge_pr_delegates(pr, with_token):
    respx.get(f"{BASE_URL}/merge_requests/{PR_NUM}").mock(
        return_value=httpx.Response(200, json={"state": "opened", "sha": "abc123"})
    )
    respx.put(f"{BASE_URL}/merge_requests/{PR_NUM}/merge").mock(
        return_value=httpx.Response(200, json={})
    )
    from activities.platform_activities import merge_pr

    env = ActivityEnvironment()
    await env.run(merge_pr, pr)


@respx.mock
async def test_platform_activity_close_pr_delegates(pr, with_token):
    respx.post(f"{BASE_URL}/merge_requests/{PR_NUM}/notes").mock(
        return_value=httpx.Response(201, json={})
    )
    respx.put(f"{BASE_URL}/merge_requests/{PR_NUM}").mock(return_value=httpx.Response(200, json={}))
    from activities.platform_activities import close_pr

    env = ActivityEnvironment()
    await env.run(close_pr, pr, "test reason")


@respx.mock
async def test_platform_activity_label_delegates(pr, with_token):
    respx.put(f"{BASE_URL}/merge_requests/{PR_NUM}").mock(return_value=httpx.Response(200, json={}))
    from activities.platform_activities import label

    env = ActivityEnvironment()
    await env.run(label, pr, "triage-red")


@respx.mock
async def test_platform_activity_request_review_delegates(pr, with_token):
    respx.get(USERS_URL).mock(return_value=httpx.Response(200, json=[{"id": 1}]))
    respx.put(f"{BASE_URL}/merge_requests/{PR_NUM}").mock(return_value=httpx.Response(200, json={}))
    from activities.platform_activities import request_review

    env = ActivityEnvironment()
    await env.run(request_review, pr, ["alice"])


@respx.mock
async def test_platform_activity_check_pr_files_delegates(pr, with_token):
    respx.get(f"{BASE_URL}/merge_requests/{PR_NUM}/changes").mock(
        return_value=httpx.Response(200, json={"changes": []})
    )
    from activities.platform_activities import check_pr_files

    env = ActivityEnvironment()
    result = await env.run(check_pr_files, pr)
    assert result.unexpected_files == []
