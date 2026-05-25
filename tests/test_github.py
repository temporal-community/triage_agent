"""
Tests for activities/platform/github.py (GitHubPlatformClient).

All non-dry-run tests set GITHUB_TOKEN (PAT path) to bypass GitHub App auth.
HTTP calls are mocked with respx.
"""

import json

import httpx
import pytest
import respx
from temporalio.exceptions import ApplicationError
from temporalio.testing import ActivityEnvironment

from platforms.github import GitHubPlatformClient, _is_ci_infra_file
from models import PRContext, PRFilesChecks, Verdict


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

REPO = "owner/repo"
PR_NUM = 42
INSTALL_ID = 123
BASE_URL = f"https://api.github.com/repos/{REPO}"


@pytest.fixture
def client():
    return GitHubPlatformClient(installation_id=INSTALL_ID)


@pytest.fixture
def pr():
    return PRContext(
        repo=REPO,
        pr_number=PR_NUM,
        pr_author="dependabot[bot]",
        installation_id=INSTALL_ID,
        platform="github",
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
def with_pat(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghs_test_pat")
    monkeypatch.delenv("GITHUB_APP_ID", raising=False)


@pytest.fixture
def dry_run(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_APP_ID", raising=False)


def _open_pr_payload(sha: str = "abc123") -> dict:
    return {"state": "open", "head": {"sha": sha}, "mergeable": True, "mergeable_state": "clean"}


# ---------------------------------------------------------------------------
# _dry_run
# ---------------------------------------------------------------------------


def test_dry_run_true_when_no_credentials(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_APP_ID", raising=False)
    assert GitHubPlatformClient()._dry_run() is True


def test_dry_run_false_with_pat(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghs_test")
    monkeypatch.delenv("GITHUB_APP_ID", raising=False)
    assert GitHubPlatformClient()._dry_run() is False


def test_dry_run_false_with_app_id(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setenv("GITHUB_APP_ID", "12345")
    assert GitHubPlatformClient()._dry_run() is False


# ---------------------------------------------------------------------------
# comment
# ---------------------------------------------------------------------------


@respx.mock
async def test_comment_dry_run_makes_no_http_call(client, pr, verdict, dry_run):
    env = ActivityEnvironment()
    await env.run(client.comment, pr, verdict)


@respx.mock
async def test_comment_posts_to_correct_url(client, pr, verdict, with_pat):
    route = respx.post(f"{BASE_URL}/issues/{PR_NUM}/comments").mock(
        return_value=httpx.Response(201, json={})
    )
    env = ActivityEnvironment()
    await env.run(client.comment, pr, verdict)
    assert route.called


@respx.mock
async def test_comment_body_contains_verdict_badge(client, pr, verdict, with_pat):
    route = respx.post(f"{BASE_URL}/issues/{PR_NUM}/comments").mock(
        return_value=httpx.Response(201, json={})
    )
    env = ActivityEnvironment()
    await env.run(client.comment, pr, verdict)
    body = route.calls[0].request.content.decode()
    assert "GREEN" in body


@respx.mock
async def test_comment_401_raises_non_retryable(client, pr, verdict, with_pat):
    respx.post(f"{BASE_URL}/issues/{PR_NUM}/comments").mock(return_value=httpx.Response(401))
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
async def test_merge_pr_pr_not_open_raises_non_retryable(client, pr, with_pat):
    respx.get(f"{BASE_URL}/pulls/{PR_NUM}").mock(
        return_value=httpx.Response(200, json={"state": "closed", "head": {"sha": "abc123"}})
    )
    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(client.merge_pr, pr)
    assert exc_info.value.non_retryable is True
    assert "closed" in str(exc_info.value)


@respx.mock
async def test_merge_pr_sha_mismatch_raises_non_retryable(client, pr, with_pat):
    respx.get(f"{BASE_URL}/pulls/{PR_NUM}").mock(
        return_value=httpx.Response(200, json=_open_pr_payload(sha="different_sha"))
    )
    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(client.merge_pr, pr)
    assert exc_info.value.non_retryable is True
    assert "SHA" in str(exc_info.value)


@respx.mock
async def test_merge_pr_skips_sha_check_when_head_sha_empty(client, pr, with_pat):
    pr.head_sha = ""
    respx.get(f"{BASE_URL}/pulls/{PR_NUM}").mock(
        return_value=httpx.Response(200, json=_open_pr_payload(sha="anything"))
    )
    respx.put(f"{BASE_URL}/pulls/{PR_NUM}/merge").mock(
        return_value=httpx.Response(200, json={"merged": True})
    )
    env = ActivityEnvironment()
    await env.run(client.merge_pr, pr)


@respx.mock
async def test_merge_pr_405_is_retryable(client, pr, with_pat):
    respx.get(f"{BASE_URL}/pulls/{PR_NUM}").mock(
        return_value=httpx.Response(200, json=_open_pr_payload())
    )
    respx.put(f"{BASE_URL}/pulls/{PR_NUM}/merge").mock(
        return_value=httpx.Response(405, json={"message": "not mergeable"})
    )
    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(client.merge_pr, pr)
    assert exc_info.value.non_retryable is False


@respx.mock
async def test_merge_pr_422_is_non_retryable(client, pr, with_pat):
    respx.get(f"{BASE_URL}/pulls/{PR_NUM}").mock(
        return_value=httpx.Response(200, json=_open_pr_payload())
    )
    respx.put(f"{BASE_URL}/pulls/{PR_NUM}/merge").mock(
        return_value=httpx.Response(422, json={"message": "merge conflict"})
    )
    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(client.merge_pr, pr)
    assert exc_info.value.non_retryable is True
    assert "merge conflict" in str(exc_info.value)


@respx.mock
async def test_merge_pr_success_uses_squash(client, pr, with_pat):
    respx.get(f"{BASE_URL}/pulls/{PR_NUM}").mock(
        return_value=httpx.Response(200, json=_open_pr_payload())
    )
    merge_route = respx.put(f"{BASE_URL}/pulls/{PR_NUM}/merge").mock(
        return_value=httpx.Response(200, json={"merged": True})
    )
    env = ActivityEnvironment()
    await env.run(client.merge_pr, pr)

    body = json.loads(merge_route.calls[0].request.content)
    assert body["merge_method"] == "squash"
    assert body["sha"] == "abc123"


# ---------------------------------------------------------------------------
# request_review
# ---------------------------------------------------------------------------


@respx.mock
async def test_request_review_dry_run_makes_no_http_call(client, pr, dry_run):
    env = ActivityEnvironment()
    await env.run(client.request_review, pr, ["alice", "bob"])


@respx.mock
async def test_request_review_posts_reviewers(client, pr, with_pat):
    route = respx.post(f"{BASE_URL}/pulls/{PR_NUM}/requested_reviewers").mock(
        return_value=httpx.Response(201, json={})
    )
    env = ActivityEnvironment()
    await env.run(client.request_review, pr, ["alice", "bob"])

    body = json.loads(route.calls[0].request.content)
    assert body["reviewers"] == ["alice", "bob"]


# ---------------------------------------------------------------------------
# label
# ---------------------------------------------------------------------------


@respx.mock
async def test_label_dry_run_makes_no_http_call(client, pr, dry_run):
    env = ActivityEnvironment()
    await env.run(client.label, pr, "supply-chain-suspicious")


@respx.mock
async def test_label_posts_to_correct_url(client, pr, with_pat):
    route = respx.post(f"{BASE_URL}/issues/{PR_NUM}/labels").mock(
        return_value=httpx.Response(200, json=[])
    )
    env = ActivityEnvironment()
    await env.run(client.label, pr, "supply-chain-suspicious")

    body = json.loads(route.calls[0].request.content)
    assert body["labels"] == ["supply-chain-suspicious"]


# ---------------------------------------------------------------------------
# close_pr
# ---------------------------------------------------------------------------


@respx.mock
async def test_close_pr_dry_run_makes_no_http_call(client, pr, dry_run):
    env = ActivityEnvironment()
    await env.run(client.close_pr, pr, "Suspicious release.")


@respx.mock
async def test_close_pr_posts_comment_then_patches_pr(client, pr, with_pat):
    comment_route = respx.post(f"{BASE_URL}/issues/{PR_NUM}/comments").mock(
        return_value=httpx.Response(201, json={})
    )
    close_route = respx.patch(f"{BASE_URL}/pulls/{PR_NUM}").mock(
        return_value=httpx.Response(200, json={})
    )
    env = ActivityEnvironment()
    await env.run(client.close_pr, pr, "Suspicious release.")

    assert comment_route.called
    assert close_route.called
    close_body = json.loads(close_route.calls[0].request.content)
    assert close_body["state"] == "closed"


@respx.mock
async def test_close_pr_with_ignore_bot_includes_magic_phrase(client, pr, with_pat):
    respx.post(f"{BASE_URL}/issues/{PR_NUM}/comments").mock(
        return_value=httpx.Response(201, json={})
    )
    respx.patch(f"{BASE_URL}/pulls/{PR_NUM}").mock(return_value=httpx.Response(200, json={}))
    comment_route = respx.post(f"{BASE_URL}/issues/{PR_NUM}/comments").mock(
        return_value=httpx.Response(201, json={})
    )
    env = ActivityEnvironment()
    await env.run(client.close_pr, pr, "Blocked.", ignore_bot=True)

    comment_body = comment_route.calls[0].request.content.decode()
    assert "@dependabot ignore this dependency" in comment_body


@respx.mock
async def test_close_pr_422_raises_non_retryable(client, pr, with_pat):
    respx.post(f"{BASE_URL}/issues/{PR_NUM}/comments").mock(
        return_value=httpx.Response(201, json={})
    )
    respx.patch(f"{BASE_URL}/pulls/{PR_NUM}").mock(
        return_value=httpx.Response(422, json={"message": "already closed"})
    )
    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(client.close_pr, pr, "Blocked.")
    assert exc_info.value.non_retryable is True
    assert "already closed" in str(exc_info.value)


# ---------------------------------------------------------------------------
# _is_ci_infra_file (unit tests — no HTTP)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        ".github/workflows/ci.yml",
        ".github/workflows/release.yaml",
        ".github/actions/setup/action.yml",
        ".github/CODEOWNERS",
        ".github/dependabot.yml",
        ".github/triage-agent.yml",
        ".gitlab-ci.yml",
        ".gitlab-ci.yaml",
        "Jenkinsfile",
        ".circleci/config.yml",
        ".buildkite/pipeline.yml",
        ".travis.yml",
        ".travis.yaml",
        "bitbucket-pipelines.yml",
        ".drone.yml",
        "appveyor.yml",
        "Dockerfile",
        "Dockerfile.prod",
        "dockerfile",
        "docker-compose.yml",
        "docker-compose.override.yaml",
        ".dockerignore",
        "Makefile",
        "makefile",
        "GNUmakefile",
        "scripts/deploy.sh",
        "deploy.bash",
        "build.ps1",
        "install.bat",
        "run.cmd",
        # AI assistant / IDE hook files that can run code on load
        ".claude/settings.json",
        ".claude/settings.local.json",
        ".cursor/rules",
        ".cursorrules",
        ".vscode/tasks.json",
        ".vscode/launch.json",
        ".vscode/extensions.json",
        ".idea/workspace.xml",
        ".idea/runConfigurations",
        ".devcontainer/devcontainer.json",
        ".devcontainer.json",
    ],
)
def test_is_ci_infra_file_detects_suspicious(path):
    assert _is_ci_infra_file(path) is True


@pytest.mark.parametrize(
    "path",
    [
        "requirements.txt",
        "package.json",
        "package-lock.json",
        "Gemfile",
        "Gemfile.lock",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "src/main.py",
        "lib/utils.js",
        "README.md",
        "CHANGELOG.md",
    ],
)
def test_is_ci_infra_file_passes_dep_files(path):
    assert _is_ci_infra_file(path) is False


# ---------------------------------------------------------------------------
# check_pr_files
# ---------------------------------------------------------------------------


@respx.mock
async def test_check_pr_files_dry_run_returns_empty(client, pr, dry_run):
    env = ActivityEnvironment()
    result = await env.run(client.check_pr_files, pr)
    assert result == PRFilesChecks()
    assert result.unexpected_files == []


@respx.mock
async def test_check_pr_files_clean_pr_returns_empty(client, pr, with_pat):
    respx.get(f"{BASE_URL}/pulls/{PR_NUM}/files").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"filename": "requirements.txt"},
                {"filename": "requirements-dev.txt"},
            ],
        )
    )
    env = ActivityEnvironment()
    result = await env.run(client.check_pr_files, pr)
    assert result.unexpected_files == []


@respx.mock
async def test_check_pr_files_detects_workflow_file(client, pr, with_pat):
    respx.get(f"{BASE_URL}/pulls/{PR_NUM}/files").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"filename": "requirements.txt"},
                {"filename": ".github/workflows/ci.yml"},
            ],
        )
    )
    env = ActivityEnvironment()
    result = await env.run(client.check_pr_files, pr)
    assert result.unexpected_files == [".github/workflows/ci.yml"]


@respx.mock
async def test_check_pr_files_detects_multiple_suspicious_files(client, pr, with_pat):
    respx.get(f"{BASE_URL}/pulls/{PR_NUM}/files").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"filename": "package.json"},
                {"filename": "Dockerfile"},
                {"filename": "deploy.sh"},
                {"filename": ".github/workflows/release.yml"},
            ],
        )
    )
    env = ActivityEnvironment()
    result = await env.run(client.check_pr_files, pr)
    assert set(result.unexpected_files) == {
        "Dockerfile",
        "deploy.sh",
        ".github/workflows/release.yml",
    }


@respx.mock
async def test_check_pr_files_401_raises_non_retryable(client, pr, with_pat):
    respx.get(f"{BASE_URL}/pulls/{PR_NUM}/files").mock(return_value=httpx.Response(401))
    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(client.check_pr_files, pr)
    assert exc_info.value.non_retryable is True


# ---------------------------------------------------------------------------
# NotificationChannel — PlatformCommentChannel is the default
# ---------------------------------------------------------------------------


@respx.mock
async def test_notification_channel_default_is_platform_comment(pr, verdict, with_pat):
    """get_notification_channels() returns PlatformCommentChannel by default."""
    from helpers.notification import get_notification_channels, PlatformCommentChannel

    channel = get_notification_channels()
    assert isinstance(channel, PlatformCommentChannel)


@respx.mock
async def test_notification_multi_channel_when_slack_url_set(pr, verdict, with_pat, monkeypatch):
    """Setting TRIAGE_NOTIFY_SLACK_WEBHOOK_URL adds a SlackWebhookChannel."""
    monkeypatch.setenv("TRIAGE_NOTIFY_SLACK_WEBHOOK_URL", "https://hooks.slack.com/test")
    from helpers.notification import get_notification_channels, MultiChannel

    channel = get_notification_channels()
    assert isinstance(channel, MultiChannel)


@respx.mock
async def test_notification_multi_channel_when_webhook_url_set(pr, verdict, with_pat, monkeypatch):
    """Setting TRIAGE_NOTIFY_WEBHOOK_URL adds a WebhookChannel."""
    monkeypatch.setenv("TRIAGE_NOTIFY_WEBHOOK_URL", "https://example.com/hook")
    from helpers.notification import get_notification_channels, MultiChannel

    channel = get_notification_channels()
    assert isinstance(channel, MultiChannel)


@respx.mock
async def test_platform_comment_channel_posts_to_github_pr(pr, verdict, with_pat):
    """PlatformCommentChannel routes GitHub PRs to the GitHub Issues API."""
    from helpers.notification import PlatformCommentChannel
    from temporalio.testing import ActivityEnvironment

    route = respx.post(f"{BASE_URL}/issues/{PR_NUM}/comments").mock(
        return_value=httpx.Response(201, json={})
    )
    env = ActivityEnvironment()
    await env.run(lambda: PlatformCommentChannel().send_verdict(pr, verdict))
    assert route.called


@respx.mock
async def test_slack_channel_failure_is_non_fatal(pr, verdict, monkeypatch):
    """SlackWebhookChannel swallows exceptions to avoid disrupting the workflow."""
    from helpers.notification import SlackWebhookChannel

    respx.post("https://hooks.slack.com/test").mock(return_value=httpx.Response(500))
    env = ActivityEnvironment()
    # Should not raise
    await env.run(
        lambda: SlackWebhookChannel("https://hooks.slack.com/test").send_verdict(pr, verdict)
    )


@respx.mock
async def test_slack_channel_uses_gitlab_url_for_gitlab_pr(verdict):
    """SlackWebhookChannel builds a GitLab MR URL when pr.platform == 'gitlab'."""
    from helpers.notification import SlackWebhookChannel

    gitlab_pr = PRContext(
        repo=REPO,
        pr_number=PR_NUM,
        pr_author="renovate[bot]",
        installation_id=None,
        platform="gitlab",
        ecosystem="pip",
        package_name="requests",
        old_version="2.31.0",
        new_version="2.32.0",
    )
    route = respx.post("https://hooks.slack.com/test").mock(return_value=httpx.Response(200))
    env = ActivityEnvironment()
    await env.run(
        lambda: SlackWebhookChannel("https://hooks.slack.com/test").send_verdict(gitlab_pr, verdict)
    )
    assert route.called
    body = route.calls[0].request.content.decode()
    assert "merge_requests" in body
    assert f"!{PR_NUM}" in body


@respx.mock
async def test_webhook_channel_posts_json_payload(pr, verdict):
    """WebhookChannel POSTs JSON with pr, verdict, and signals."""
    from helpers.notification import WebhookChannel

    route = respx.post("https://example.com/hook").mock(return_value=httpx.Response(200))
    env = ActivityEnvironment()
    await env.run(lambda: WebhookChannel("https://example.com/hook").send_verdict(pr, verdict))
    assert route.called
    import json

    body = json.loads(route.calls[0].request.content)
    assert "pr" in body
    assert "verdict" in body
    assert body["signals"] is None


@respx.mock
async def test_webhook_channel_failure_is_non_fatal(pr, verdict):
    """WebhookChannel swallows exceptions to avoid disrupting the workflow."""
    from helpers.notification import WebhookChannel

    respx.post("https://example.com/hook").mock(return_value=httpx.Response(503))
    env = ActivityEnvironment()
    # Should not raise
    await env.run(lambda: WebhookChannel("https://example.com/hook").send_verdict(pr, verdict))


@respx.mock
async def test_multi_channel_fans_out_to_all_channels(pr, verdict, with_pat):
    """MultiChannel.send_verdict delivers to all configured channels."""
    from helpers.notification import MultiChannel, PlatformCommentChannel, SlackWebhookChannel

    comment_route = respx.post(f"{BASE_URL}/issues/{PR_NUM}/comments").mock(
        return_value=httpx.Response(201, json={})
    )
    slack_route = respx.post("https://hooks.slack.com/test").mock(return_value=httpx.Response(200))
    ch = MultiChannel(
        [PlatformCommentChannel(), SlackWebhookChannel("https://hooks.slack.com/test")]
    )
    env = ActivityEnvironment()
    await env.run(lambda: ch.send_verdict(pr, verdict))
    assert comment_route.called
    assert slack_route.called
