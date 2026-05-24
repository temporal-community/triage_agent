import httpx
import pytest
import respx
from temporalio.exceptions import ApplicationError
from temporalio.testing import ActivityEnvironment

from activities.socket import score

PURL_URL = "https://api.socket.dev/v0/purl"


def _socket_response(depscore: float, alerts: list[dict]) -> dict:
    return {
        "packages": [
            {
                "purl": "pkg:pypi/requests@2.32.0",
                "score": {"depscore": depscore},
                "alerts": alerts,
            }
        ]
    }


async def test_no_api_key_returns_empty(monkeypatch):
    monkeypatch.delenv("SOCKET_API_KEY", raising=False)
    env = ActivityEnvironment()
    result = await env.run(score, "pip", "requests", "2.31.0", "2.32.0")
    assert result.socket_score is None
    assert result.socket_alerts == []


@respx.mock
async def test_score_and_alerts_parsed(monkeypatch):
    monkeypatch.setenv("SOCKET_API_KEY", "test-key")
    respx.post(PURL_URL).mock(
        return_value=httpx.Response(
            200,
            json=_socket_response(
                depscore=0.72,
                alerts=[
                    {
                        "severity": "high",
                        "type": "install-scripts",
                        "message": "Runs code at install time",
                    },
                    {
                        "severity": "critical",
                        "type": "obfuscated-code",
                        "message": "Base64-encoded payload",
                    },
                    {
                        "severity": "low",
                        "type": "env-vars",
                        "message": "Reads environment variables",
                    },
                ],
            ),
        )
    )
    env = ActivityEnvironment()
    result = await env.run(score, "pip", "requests", "2.31.0", "2.32.0")
    assert result.socket_score == 72
    # Only high/critical included
    assert len(result.socket_alerts) == 2
    assert any("install-scripts" in a for a in result.socket_alerts)
    assert any("obfuscated-code" in a for a in result.socket_alerts)
    assert not any("env-vars" in a for a in result.socket_alerts)


@respx.mock
async def test_score_converted_to_0_100(monkeypatch):
    monkeypatch.setenv("SOCKET_API_KEY", "test-key")
    respx.post(PURL_URL).mock(
        return_value=httpx.Response(200, json=_socket_response(depscore=0.856, alerts=[]))
    )
    env = ActivityEnvironment()
    result = await env.run(score, "pip", "requests", "2.31.0", "2.32.0")
    assert result.socket_score == 86  # round(0.856 * 100)


@respx.mock
async def test_package_not_found_returns_empty(monkeypatch):
    monkeypatch.setenv("SOCKET_API_KEY", "test-key")
    respx.post(PURL_URL).mock(return_value=httpx.Response(404))
    env = ActivityEnvironment()
    result = await env.run(score, "pip", "obscure-pkg", "1.0.0", "1.0.1")
    assert result.socket_score is None
    assert result.socket_alerts == []


@respx.mock
async def test_auth_failure_raises_non_retryable(monkeypatch):
    monkeypatch.setenv("SOCKET_API_KEY", "bad-key")
    respx.post(PURL_URL).mock(return_value=httpx.Response(401))
    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(score, "pip", "requests", "2.31.0", "2.32.0")
    assert exc_info.value.non_retryable is True


@respx.mock
async def test_empty_packages_list_returns_empty(monkeypatch):
    monkeypatch.setenv("SOCKET_API_KEY", "test-key")
    respx.post(PURL_URL).mock(return_value=httpx.Response(200, json={"packages": []}))
    env = ActivityEnvironment()
    result = await env.run(score, "pip", "requests", "2.31.0", "2.32.0")
    assert result.socket_score is None


@respx.mock
async def test_purl_uses_correct_ecosystem(monkeypatch):
    monkeypatch.setenv("SOCKET_API_KEY", "test-key")
    route = respx.post(PURL_URL).mock(
        return_value=httpx.Response(200, json=_socket_response(0.9, []))
    )
    env = ActivityEnvironment()
    await env.run(score, "npm", "express", "4.18.1", "4.18.2")
    import json

    body = json.loads(route.calls[0].request.content)
    assert body["components"][0]["purl"] == "pkg:npm/express@4.18.2"


@respx.mock
async def test_rate_limited_raises_retryable(monkeypatch):
    monkeypatch.setenv("SOCKET_API_KEY", "test-key")
    respx.post(PURL_URL).mock(return_value=httpx.Response(429))
    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(score, "pip", "requests", "2.31.0", "2.32.0")
    assert exc_info.value.non_retryable is False
    assert "rate limited" in str(exc_info.value).lower()
