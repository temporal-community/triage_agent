"""
Tests for the FastAPI webhook receiver.

Uses httpx.AsyncClient with ASGITransport so tests run in-process.
The Temporal client is mocked so no real Temporal server is needed.
"""

import hashlib
import hmac
import json
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

TEST_SECRET = "test-webhook-secret"
TEST_REPO = "owner/repo"
TEST_PR_NUMBER = 42


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sign(body: bytes, secret: str = TEST_SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


TEST_HEAD_SHA = "abc123def456abc123def456abc123def456abc1"  # 40-char hex SHA-1


def _dependabot_payload(
    action: str = "opened",
    title: str = "Bump requests from 2.31.0 to 2.32.0",
    author: str = "dependabot[bot]",
    pr_number: int = TEST_PR_NUMBER,
    installation_id: int = 12345,
    branch: str = "dependabot/pip/requests-2.32.0",
) -> bytes:
    payload = {
        "action": action,
        "pull_request": {
            "number": pr_number,
            "title": title,
            "body": "",
            "user": {"login": author},
            "head": {"sha": TEST_HEAD_SHA, "ref": branch},
        },
        "repository": {"full_name": TEST_REPO},
        "installation": {"id": installation_id},
    }
    return json.dumps(payload).encode()


@pytest.fixture
async def client(monkeypatch):
    """AsyncClient with mocked Temporal — no real server needed.

    ASGITransport does not trigger FastAPI lifespan, so we inject the mock
    Temporal client directly into the module-level variable instead.
    """
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", TEST_SECRET)

    mock_tc = AsyncMock()
    mock_tc.start_workflow = AsyncMock(return_value=MagicMock(id="wf-id"))

    import api.webhook as webhook_module

    monkeypatch.setattr(webhook_module, "_temporal_client", mock_tc)

    from api.webhook import app

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac, mock_tc


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------


async def test_dependabot_pr_starts_workflow(client):
    ac, mock_tc = client
    body = _dependabot_payload()
    resp = await ac.post(
        "/webhook",
        content=body,
        headers={"X-Hub-Signature-256": _sign(body), "X-GitHub-Event": "pull_request"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "started"
    assert "pr-action-owner-repo-42" in data["workflow_id"]
    mock_tc.start_workflow.assert_called_once()


async def test_renovate_pr_starts_workflow(client):
    ac, mock_tc = client
    body = _dependabot_payload(
        title="Update dependency requests to v2.32.0",
        author="renovate[bot]",
    )
    resp = await ac.post(
        "/webhook",
        content=body,
        headers={"X-Hub-Signature-256": _sign(body), "X-GitHub-Event": "pull_request"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "started"


async def test_workflow_id_uses_repo_and_pr_number(client):
    ac, mock_tc = client
    body = _dependabot_payload(pr_number=99)
    await ac.post(
        "/webhook",
        content=body,
        headers={"X-Hub-Signature-256": _sign(body), "X-GitHub-Event": "pull_request"},
    )
    _, kwargs = mock_tc.start_workflow.call_args
    assert kwargs["id"] == "pr-action-owner-repo-99"


async def test_pr_context_fields_correct(client):
    ac, mock_tc = client
    body = _dependabot_payload(installation_id=99999)
    await ac.post(
        "/webhook",
        content=body,
        headers={"X-Hub-Signature-256": _sign(body), "X-GitHub-Event": "pull_request"},
    )
    args, _ = mock_tc.start_workflow.call_args
    pr_context = args[1]
    assert pr_context.repo == TEST_REPO
    assert pr_context.pr_number == TEST_PR_NUMBER
    assert pr_context.ecosystem == "pip"
    assert pr_context.package_name == "requests"
    assert pr_context.old_version == "2.31.0"
    assert pr_context.new_version == "2.32.0"
    assert pr_context.installation_id == 99999
    assert pr_context.head_sha == TEST_HEAD_SHA


# ---------------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------------


async def test_invalid_signature_returns_401(client):
    ac, _ = client
    body = _dependabot_payload()
    resp = await ac.post(
        "/webhook",
        content=body,
        headers={
            "X-Hub-Signature-256": _sign(body, "wrong-secret"),
            "X-GitHub-Event": "pull_request",
        },
    )
    assert resp.status_code == 401


async def test_missing_signature_header_returns_422(client):
    ac, _ = client
    body = _dependabot_payload()
    resp = await ac.post(
        "/webhook",
        content=body,
        headers={"X-GitHub-Event": "pull_request"},
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Filtering — all should return 200 "ignored"
# ---------------------------------------------------------------------------


async def test_non_pr_event_ignored(client):
    ac, mock_tc = client
    body = _dependabot_payload()
    resp = await ac.post(
        "/webhook",
        content=body,
        headers={"X-Hub-Signature-256": _sign(body), "X-GitHub-Event": "push"},
    )
    assert resp.json()["status"] == "ignored"
    mock_tc.start_workflow.assert_not_called()


async def test_closed_action_ignored(client):
    ac, mock_tc = client
    body = _dependabot_payload(action="closed")
    resp = await ac.post(
        "/webhook",
        content=body,
        headers={"X-Hub-Signature-256": _sign(body), "X-GitHub-Event": "pull_request"},
    )
    assert resp.json()["status"] == "ignored"
    mock_tc.start_workflow.assert_not_called()


async def test_human_author_ignored(client):
    ac, mock_tc = client
    body = _dependabot_payload(author="octocat")
    resp = await ac.post(
        "/webhook",
        content=body,
        headers={"X-Hub-Signature-256": _sign(body), "X-GitHub-Event": "pull_request"},
    )
    assert resp.json()["status"] == "ignored"
    mock_tc.start_workflow.assert_not_called()


async def test_unparseable_title_ignored(client):
    ac, mock_tc = client
    body = _dependabot_payload(title="chore: update CI config")
    resp = await ac.post(
        "/webhook",
        content=body,
        headers={"X-Hub-Signature-256": _sign(body), "X-GitHub-Event": "pull_request"},
    )
    assert resp.json()["status"] == "ignored"
    mock_tc.start_workflow.assert_not_called()


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


async def test_healthz(client):
    ac, _ = client
    resp = await ac.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


# ---------------------------------------------------------------------------
# Input validation — package name / version
# ---------------------------------------------------------------------------


async def test_path_traversal_in_package_name_ignored(client):
    ac, mock_tc = client
    body = _dependabot_payload(title="Bump ../../../etc/passwd from 1.0.0 to 1.0.1")
    resp = await ac.post(
        "/webhook",
        content=body,
        headers={"X-Hub-Signature-256": _sign(body), "X-GitHub-Event": "pull_request"},
    )
    assert resp.json()["status"] == "ignored"
    mock_tc.start_workflow.assert_not_called()


async def test_newline_in_package_name_ignored(client):
    ac, mock_tc = client
    body = _dependabot_payload(title="Bump requests\nevil from 2.31.0 to 2.32.0")
    resp = await ac.post(
        "/webhook",
        content=body,
        headers={"X-Hub-Signature-256": _sign(body), "X-GitHub-Event": "pull_request"},
    )
    # Either ignored (regex won't match) or invalid name — either way no workflow
    assert resp.json()["status"] == "ignored"
    mock_tc.start_workflow.assert_not_called()


async def test_valid_scoped_npm_package_accepted(client):
    ac, mock_tc = client
    body = _dependabot_payload(
        title="Bump @typescript-eslint/parser from 6.0.0 to 6.1.0",
        branch="dependabot/npm_and_yarn/@typescript-eslint/parser-6.1.0",
    )
    resp = await ac.post(
        "/webhook",
        content=body,
        headers={"X-Hub-Signature-256": _sign(body), "X-GitHub-Event": "pull_request"},
    )
    assert resp.json()["status"] == "started"
    mock_tc.start_workflow.assert_called_once()


def test_validate_package_rejects_path_traversal():
    from api.webhook import _validate_parsed_package

    assert _validate_parsed_package("pip", "../evil", "1.0.0", "1.0.1") is not None


def test_validate_package_rejects_semicolon():
    from api.webhook import _validate_parsed_package

    assert _validate_parsed_package("pip", "requests; rm -rf /", "1.0.0", "1.0.1") is not None


def test_validate_package_rejects_null_byte():
    from api.webhook import _validate_parsed_package

    assert _validate_parsed_package("npm", "lodash\x00evil", "1.0.0", "1.0.1") is not None


def test_validate_package_accepts_normal_pypi():
    from api.webhook import _validate_parsed_package

    assert _validate_parsed_package("pip", "requests", "2.31.0", "2.32.0") is None


def test_validate_package_accepts_scoped_npm():
    from api.webhook import _validate_parsed_package

    assert _validate_parsed_package("npm", "@typescript-eslint/parser", "6.0.0", "6.1.0") is None


def test_validate_package_accepts_unknown_old_version():
    from api.webhook import _validate_parsed_package

    assert _validate_parsed_package("pip", "requests", "unknown", "2.32.0") is None


# ---------------------------------------------------------------------------
# pull_request_review handling
# ---------------------------------------------------------------------------


def _review_payload(
    state: str = "approved",
    action: str = "submitted",
    reviewer: str = "alice",
    pr_number: int = TEST_PR_NUMBER,
) -> bytes:
    payload = {
        "action": action,
        "review": {"state": state, "user": {"login": reviewer}},
        "pull_request": {"number": pr_number},
        "repository": {"full_name": TEST_REPO},
    }
    return json.dumps(payload).encode()


async def test_approved_review_signals_workflow(client):
    ac, mock_tc = client
    mock_handle = AsyncMock()
    mock_tc.get_workflow_handle = MagicMock(return_value=mock_handle)

    body = _review_payload(state="approved", reviewer="alice")
    resp = await ac.post(
        "/webhook",
        content=body,
        headers={"X-Hub-Signature-256": _sign(body), "X-GitHub-Event": "pull_request_review"},
    )
    assert resp.json()["status"] == "signalled"
    assert resp.json()["decision"] == "approve"
    mock_handle.signal.assert_called_once()
    # signal is called as: handle.signal(func, args=[decision, reviewer])
    signal_args = mock_handle.signal.call_args.kwargs.get("args", [])
    assert signal_args[1] == "alice"


async def test_changes_requested_review_signals_reject(client):
    ac, mock_tc = client
    mock_handle = AsyncMock()
    mock_tc.get_workflow_handle = MagicMock(return_value=mock_handle)

    body = _review_payload(state="changes_requested", reviewer="bob")
    resp = await ac.post(
        "/webhook",
        content=body,
        headers={"X-Hub-Signature-256": _sign(body), "X-GitHub-Event": "pull_request_review"},
    )
    assert resp.json()["status"] == "signalled"
    assert resp.json()["decision"] == "reject"


async def test_commented_review_is_ignored(client):
    ac, mock_tc = client
    body = _review_payload(state="commented")
    resp = await ac.post(
        "/webhook",
        content=body,
        headers={"X-Hub-Signature-256": _sign(body), "X-GitHub-Event": "pull_request_review"},
    )
    assert resp.json()["status"] == "ignored"


async def test_review_dismissed_action_is_ignored(client):
    ac, mock_tc = client
    body = _review_payload(action="dismissed")
    resp = await ac.post(
        "/webhook",
        content=body,
        headers={"X-Hub-Signature-256": _sign(body), "X-GitHub-Event": "pull_request_review"},
    )
    assert resp.json()["status"] == "ignored"


async def test_review_no_active_workflow_is_ignored(client):
    ac, mock_tc = client
    mock_handle = AsyncMock()
    mock_handle.signal.side_effect = Exception("workflow not found")
    mock_tc.get_workflow_handle = MagicMock(return_value=mock_handle)

    body = _review_payload(state="approved")
    resp = await ac.post(
        "/webhook",
        content=body,
        headers={"X-Hub-Signature-256": _sign(body), "X-GitHub-Event": "pull_request_review"},
    )
    assert resp.json()["status"] == "ignored"


async def test_review_bad_signature_rejected(client):
    ac, _ = client
    body = _review_payload(state="approved")
    resp = await ac.post(
        "/webhook",
        content=body,
        headers={"X-Hub-Signature-256": "sha256=badhash", "X-GitHub-Event": "pull_request_review"},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# BotParser registry
# ---------------------------------------------------------------------------


def test_get_bot_parser_returns_dependabot_parser():
    from helpers.bot_parsers import get_bot_parser, DependabotParser

    parser = get_bot_parser("dependabot[bot]")
    assert isinstance(parser, DependabotParser)


def test_get_bot_parser_returns_renovate_parser():
    from helpers.bot_parsers import get_bot_parser, RenovateParser

    parser = get_bot_parser("renovate[bot]")
    assert isinstance(parser, RenovateParser)


def test_get_bot_parser_returns_none_for_humans():
    from helpers.bot_parsers import get_bot_parser

    assert get_bot_parser("octocat") is None


def test_get_bot_logins_includes_builtins():
    from helpers.bot_parsers import get_bot_logins

    logins = get_bot_logins()
    assert "dependabot[bot]" in logins
    assert "renovate[bot]" in logins


def test_register_custom_bot_parser():
    from helpers.bot_parsers import register_bot_parser, get_bot_parser
    from helpers.pr_parser import ParsedPR

    class PyUpParser:
        bot_logins: frozenset = frozenset({"pyup-bot"})

        def parse(self, title: str, body: str, branch: str) -> ParsedPR | None:
            return None  # stub

    register_bot_parser(PyUpParser())
    assert get_bot_parser("pyup-bot") is not None
