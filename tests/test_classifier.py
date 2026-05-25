"""
Tests for activities/classifier.py.

_build_message and _rule_based are pure functions — called directly.
classify() uses ActivityEnvironment + unittest.mock to avoid real LLM calls.
"""

import pytest
import httpx
import respx
from unittest.mock import patch, AsyncMock, MagicMock
from temporalio.testing import ActivityEnvironment
from temporalio.exceptions import ApplicationError

import anthropic

from activities.classifier import classify
from classifiers import (
    _build_message,
    _rule_based,
)


# ---------------------------------------------------------------------------
# _build_message
# ---------------------------------------------------------------------------


def test_build_message_separates_diff_from_trusted(base_signals):
    msg = _build_message(base_signals)
    # diff_summary must appear only inside the untrusted XML block, not in the trusted JSON section
    trusted_section = msg.split("<untrusted_diff>")[0]
    assert '"diff_summary"' not in trusted_section
    assert "Minor internal refactor." not in trusted_section


def test_build_message_wraps_diff_in_xml_tags(base_signals):
    msg = _build_message(base_signals)
    assert "<untrusted_diff>" in msg
    assert "</untrusted_diff>" in msg
    assert "Minor internal refactor." in msg


def test_build_message_placeholder_when_no_diff(base_signals):
    base_signals.diff.diff_summary = ""
    msg = _build_message(base_signals)
    assert "[no diff available]" in msg


# ---------------------------------------------------------------------------
# _rule_based — RED path
# ---------------------------------------------------------------------------


def test_rule_based_cves_returns_red(base_signals):
    base_signals.osv.osv_vulnerabilities = ["CVE-2024-0001", "CVE-2024-0002"]
    verdict = _rule_based(base_signals)
    assert verdict.classification == "red"
    assert verdict.confidence == 0.95
    assert "CVE-2024-0001" in verdict.reasoning
    assert any("CVE-2024-0001" in f for f in verdict.flags)


# ---------------------------------------------------------------------------
# _rule_based — YELLOW paths
# ---------------------------------------------------------------------------


def test_rule_based_major_bump_is_yellow(base_signals):
    base_signals.metadata.is_major_bump = True
    verdict = _rule_based(base_signals)
    assert verdict.classification == "yellow"
    assert any("major" in f for f in verdict.flags)


def test_rule_based_very_fresh_release_is_yellow(base_signals):
    base_signals.age.release_age_hours = 10.0
    verdict = _rule_based(base_signals)
    assert verdict.classification == "yellow"
    assert any("very fresh" in f for f in verdict.flags)


def test_rule_based_recent_release_is_yellow(base_signals):
    base_signals.age.release_age_hours = 100.0  # 24 ≤ x < 168
    verdict = _rule_based(base_signals)
    assert verdict.classification == "yellow"
    assert any("recent release" in f for f in verdict.flags)


def test_rule_based_age_none_is_yellow(base_signals):
    base_signals.age.release_age_hours = None
    verdict = _rule_based(base_signals)
    assert verdict.classification == "yellow"
    assert any("unknown" in f for f in verdict.flags)


def test_rule_based_maintainer_changed_is_yellow(base_signals):
    base_signals.maintainer.maintainer_changed = True
    verdict = _rule_based(base_signals)
    assert verdict.classification == "yellow"
    assert any("maintainer" in f for f in verdict.flags)


def test_rule_based_socket_alerts_are_yellow(base_signals):
    base_signals.socket.socket_alerts = ["install script detected"]
    verdict = _rule_based(base_signals)
    assert verdict.classification == "yellow"
    assert "install script detected" in verdict.flags


def test_rule_based_low_socket_score_is_yellow(base_signals):
    base_signals.socket.socket_score = 30
    verdict = _rule_based(base_signals)
    assert verdict.classification == "yellow"
    assert any("socket score" in f for f in verdict.flags)


def test_rule_based_low_downloads_is_yellow(base_signals):
    base_signals.metadata.weekly_downloads = 500
    verdict = _rule_based(base_signals)
    assert verdict.classification == "yellow"
    assert any("download count" in f for f in verdict.flags)


def test_rule_based_yellow_carries_release_age(base_signals):
    base_signals.metadata.is_major_bump = True
    base_signals.age.release_age_hours = 72.0
    verdict = _rule_based(base_signals)
    assert verdict.release_age_hours == 72.0


def test_rule_based_multiple_flags_all_present(base_signals):
    base_signals.metadata.is_major_bump = True
    base_signals.maintainer.maintainer_changed = True
    base_signals.socket.socket_score = 35  # 30–49 range → still yellow
    verdict = _rule_based(base_signals)
    assert verdict.classification == "yellow"
    assert len(verdict.flags) >= 3


# ---------------------------------------------------------------------------
# _rule_based — GREEN path
# ---------------------------------------------------------------------------


def test_rule_based_clean_signals_are_green(base_signals):
    verdict = _rule_based(base_signals)
    assert verdict.classification == "green"
    assert verdict.confidence == 0.80
    assert verdict.flags == []


def test_rule_based_green_carries_release_age(base_signals):
    base_signals.age.release_age_hours = 300.0
    verdict = _rule_based(base_signals)
    assert verdict.release_age_hours == 300.0


def test_rule_based_green_handles_none_downloads(base_signals):
    base_signals.metadata.weekly_downloads = None
    verdict = _rule_based(base_signals)
    assert verdict.classification == "green"
    assert "unknown" in verdict.reasoning


def test_rule_based_socket_score_boundary_ok(base_signals):
    base_signals.socket.socket_score = 50  # exactly 50 → not flagged
    verdict = _rule_based(base_signals)
    assert verdict.classification == "green"


def test_rule_based_socket_score_boundary_below(base_signals):
    base_signals.socket.socket_score = 49  # one below threshold → flagged
    verdict = _rule_based(base_signals)
    assert verdict.classification == "yellow"
    assert any("socket score" in f for f in verdict.flags)


def test_rule_based_release_age_boundary_24h_is_recent(base_signals):
    base_signals.age.release_age_hours = 24.0  # exactly 24h: past "very fresh", still "recent"
    verdict = _rule_based(base_signals)
    assert verdict.classification == "yellow"
    assert any("recent release" in f for f in verdict.flags)
    assert not any("very fresh" in f for f in verdict.flags)


def test_rule_based_release_age_boundary_168h_is_green(base_signals):
    base_signals.age.release_age_hours = 168.0  # exactly one week: no longer flagged
    verdict = _rule_based(base_signals)
    assert verdict.classification == "green"


# ---------------------------------------------------------------------------
# classify — no API key falls back to rule-based
# ---------------------------------------------------------------------------


async def test_classify_no_api_key_uses_rule_based(base_signals, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    env = ActivityEnvironment()
    verdict = await env.run(classify, base_signals)
    assert verdict.classification in ("green", "yellow", "red")
    assert "[rule-based]" in verdict.reasoning


# ---------------------------------------------------------------------------
# classify — LLM success path
# ---------------------------------------------------------------------------


def _make_llm_mock(tool_input: dict) -> MagicMock:
    tool_block = MagicMock()
    tool_block.type = "tool_use"
    tool_block.input = tool_input

    response = MagicMock()
    response.content = [tool_block]

    client = MagicMock()
    client.messages.create = AsyncMock(return_value=response)

    return client


async def test_classify_llm_returns_verdict(base_signals, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    mock_client = _make_llm_mock(
        {
            "classification": "green",
            "confidence": 0.92,
            "reasoning": "Routine patch bump.",
            "flags": [],
        }
    )
    env = ActivityEnvironment()
    with patch("classifiers.anthropic.anthropic.AsyncAnthropic", return_value=mock_client):
        verdict = await env.run(classify, base_signals)

    assert verdict.classification == "green"
    assert verdict.confidence == pytest.approx(0.92)
    assert verdict.reasoning == "Routine patch bump."


async def test_classify_llm_passes_release_age_through_when_not_set(base_signals, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    base_signals.age.release_age_hours = 48.0
    # LLM omits release_age_hours (returns None by default in Verdict)
    mock_client = _make_llm_mock(
        {
            "classification": "yellow",
            "confidence": 0.7,
            "reasoning": "Recent release.",
            "flags": ["recent release"],
        }
    )
    env = ActivityEnvironment()
    with patch("classifiers.anthropic.anthropic.AsyncAnthropic", return_value=mock_client):
        verdict = await env.run(classify, base_signals)

    assert verdict.release_age_hours == 48.0


# ---------------------------------------------------------------------------
# classify — error paths
# ---------------------------------------------------------------------------


def _anthropic_response(status_code: int) -> httpx.Response:
    """Build an httpx.Response with a request attached (required by anthropic SDK exceptions)."""
    request = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    return httpx.Response(status_code, request=request)


async def test_classify_auth_error_raises_non_retryable(base_signals, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "bad-key")
    exc = anthropic.AuthenticationError("bad key", response=_anthropic_response(401), body=None)

    client = MagicMock()
    client.messages.create = AsyncMock(side_effect=exc)

    env = ActivityEnvironment()
    with patch("classifiers.anthropic.anthropic.AsyncAnthropic", return_value=client):
        with pytest.raises(ApplicationError) as exc_info:
            await env.run(classify, base_signals)

    assert exc_info.value.non_retryable is True
    assert exc_info.value.type == "AuthenticationError"


async def test_classify_bad_request_raises_non_retryable(base_signals, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    exc = anthropic.BadRequestError("bad input", response=_anthropic_response(400), body=None)

    client = MagicMock()
    client.messages.create = AsyncMock(side_effect=exc)

    env = ActivityEnvironment()
    with patch("classifiers.anthropic.anthropic.AsyncAnthropic", return_value=client):
        with pytest.raises(ApplicationError) as exc_info:
            await env.run(classify, base_signals)

    assert exc_info.value.non_retryable is True
    assert exc_info.value.type == "BadRequestError"


async def test_classify_generic_exception_falls_back_to_rule_based(base_signals, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    client = MagicMock()
    client.messages.create = AsyncMock(side_effect=RuntimeError("service unavailable"))

    env = ActivityEnvironment()
    with patch("classifiers.anthropic.anthropic.AsyncAnthropic", return_value=client):
        verdict = await env.run(classify, base_signals)

    # Falls back gracefully — still returns a valid verdict
    assert verdict.classification in ("green", "yellow", "red")


# ---------------------------------------------------------------------------
# Classifier protocol — class-based interface
# ---------------------------------------------------------------------------


async def test_rule_based_classifier_classifies(base_signals):
    from classifiers import RuleBasedClassifier

    verdict = await RuleBasedClassifier().classify(base_signals)
    assert verdict.classification in ("green", "yellow", "red")


async def test_claude_classifier_falls_back_to_rule_based_on_error(base_signals, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    from classifiers import AnthropicClassifier

    client = MagicMock()
    client.messages.create = AsyncMock(side_effect=RuntimeError("outage"))
    with patch("classifiers.anthropic.anthropic.AsyncAnthropic", return_value=client):
        verdict = await AnthropicClassifier().classify(base_signals)
    assert verdict.classification in ("green", "yellow", "red")


# ---------------------------------------------------------------------------
# get_classifier — plugin selection via CLASSIFIER env var
# ---------------------------------------------------------------------------


def test_get_classifier_defaults_to_rule_based_without_api_key(monkeypatch):
    from classifiers import RuleBasedClassifier, get_classifier

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("CLASSIFIER", raising=False)
    assert isinstance(get_classifier(), RuleBasedClassifier)


def test_get_classifier_returns_claude_when_api_key_set(monkeypatch):
    from classifiers import AnthropicClassifier, get_classifier

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.delenv("CLASSIFIER", raising=False)
    assert isinstance(get_classifier(), AnthropicClassifier)


def test_get_classifier_builtin_rule_based_name(monkeypatch):
    from classifiers import RuleBasedClassifier, get_classifier

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("CLASSIFIER", "rule_based")
    assert isinstance(get_classifier(), RuleBasedClassifier)


def test_get_classifier_builtin_claude_name(monkeypatch):
    from classifiers import AnthropicClassifier, get_classifier

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("CLASSIFIER", "claude")
    assert isinstance(get_classifier(), AnthropicClassifier)


def test_get_classifier_unknown_name_falls_back(monkeypatch):
    from classifiers import get_classifier

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("CLASSIFIER", "nonexistent_classifier_xyz")
    # Should warn and fall back gracefully rather than raise
    clf = get_classifier()
    assert clf is not None


def test_get_classifier_entry_point_plugin(monkeypatch):
    """A dependency_scout.classifiers entry point is discovered and instantiated."""
    from classifiers import RuleBasedClassifier, get_classifier

    monkeypatch.setenv("CLASSIFIER", "my_custom")

    fake_ep = MagicMock()
    fake_ep.name = "my_custom"
    fake_ep.load.return_value = RuleBasedClassifier  # returns the class

    with patch("classifiers.entry_points", return_value=[fake_ep]) as _mock_eps:
        clf = get_classifier()

    assert isinstance(clf, RuleBasedClassifier)
    fake_ep.load.assert_called_once()


def test_get_classifier_returns_rule_based_without_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    from classifiers import get_classifier, RuleBasedClassifier

    assert isinstance(get_classifier(), RuleBasedClassifier)


def test_get_classifier_returns_claude_with_key(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    from classifiers import get_classifier, AnthropicClassifier

    assert isinstance(get_classifier(), AnthropicClassifier)


def test_rule_based_artifact_source_mismatch_is_red(base_signals):
    base_signals.diff.artifact_source_mismatch = True
    base_signals.diff.artifact_source_mismatch_files = ["mypkg/__init__.py"]
    verdict = _rule_based(base_signals)
    assert verdict.classification == "red"
    assert verdict.confidence == 0.95
    assert "mypkg/__init__.py" in verdict.reasoning
    assert any("artifact/source mismatch" in f for f in verdict.flags)


def test_rule_based_artifact_mismatch_takes_priority_over_install_script(base_signals):
    """artifact_source_mismatch is checked before install_script_added — still returns red."""
    base_signals.diff.artifact_source_mismatch = True
    base_signals.diff.artifact_source_mismatch_files = ["index.js"]
    base_signals.diff.install_script_added = True
    verdict = _rule_based(base_signals)
    assert verdict.classification == "red"
    assert any("artifact/source mismatch" in f for f in verdict.flags)


# ---------------------------------------------------------------------------
# Socket alert types → hard RED
# ---------------------------------------------------------------------------


def test_rule_based_socket_malware_type_is_red(base_signals):
    """socket_alert_types containing 'malware' produces a hard RED."""
    base_signals.socket.socket_alert_types = ["malware"]
    base_signals.socket.socket_alerts = ["[critical] malware: Malicious code detected"]
    verdict = _rule_based(base_signals)
    assert verdict.classification == "red"
    assert verdict.confidence == 0.92
    assert any("malware" in f for f in verdict.flags)


def test_rule_based_socket_protestware_type_is_red(base_signals):
    """socket_alert_types containing 'protestware' produces a hard RED."""
    base_signals.socket.socket_alert_types = ["protestware"]
    verdict = _rule_based(base_signals)
    assert verdict.classification == "red"
    assert any("protestware" in f for f in verdict.flags)


def test_rule_based_socket_non_red_type_is_yellow(base_signals):
    """High-severity alert types that are not malware/protestware stay yellow."""
    base_signals.socket.socket_alert_types = ["installScripts", "networkAccess"]
    base_signals.socket.socket_alerts = ["[high] installScripts: Install script detected"]
    verdict = _rule_based(base_signals)
    assert verdict.classification == "yellow"


def test_rule_based_socket_score_below_30_is_red(base_signals):
    """Socket score < 30 produces a hard RED (packages this low are almost always malware)."""
    base_signals.socket.socket_score = 15
    verdict = _rule_based(base_signals)
    assert verdict.classification == "red"
    assert verdict.confidence == 0.88
    assert any("critically low socket score" in f for f in verdict.flags)


def test_rule_based_socket_score_exactly_30_is_yellow(base_signals):
    """Score of exactly 30 stays yellow (< 30 triggers RED, not <=)."""
    base_signals.socket.socket_score = 30
    verdict = _rule_based(base_signals)
    assert verdict.classification == "yellow"
    assert any("socket score" in f for f in verdict.flags)


def test_rule_based_socket_score_29_is_red(base_signals):
    """Score of 29 triggers the hard RED path."""
    base_signals.socket.socket_score = 29
    verdict = _rule_based(base_signals)
    assert verdict.classification == "red"


def test_rule_based_socket_malware_takes_priority_over_install_hook(base_signals):
    """Socket malware detection is checked before install_script_added."""
    base_signals.socket.socket_alert_types = ["malware"]
    base_signals.diff.install_script_added = True
    verdict = _rule_based(base_signals)
    assert verdict.classification == "red"
    assert any("malware" in f for f in verdict.flags)


# ---------------------------------------------------------------------------
# _rule_based — additional flag paths
# ---------------------------------------------------------------------------


def test_rule_based_lockfile_integrity_downgraded_is_yellow(base_signals):
    base_signals.diff.lockfile_integrity_downgraded = True
    verdict = _rule_based(base_signals)
    assert verdict.classification == "yellow"
    assert any("lockfile" in f or "integrity" in f for f in verdict.flags)


def test_rule_based_young_maintainer_account_is_yellow(base_signals):
    base_signals.maintainer.maintainer_changed = True
    base_signals.maintainer.new_maintainer_account_age_days = 30
    verdict = _rule_based(base_signals)
    assert verdict.classification == "yellow"
    assert any("30-day-old" in f for f in verdict.flags)


def test_rule_based_ci_workflow_changed_is_yellow(base_signals):
    from models import ReleaseChecks

    base_signals.release = ReleaseChecks(ci_workflow_changed_days_ago=3)
    verdict = _rule_based(base_signals)
    assert verdict.classification == "yellow"
    assert any("3 days ago" in f or "3 day" in f for f in verdict.flags)


# ---------------------------------------------------------------------------
# _build_message — custom_checks included
# ---------------------------------------------------------------------------


def test_build_message_includes_custom_checks(base_signals):
    base_signals.custom_checks = {"extra_signal": "suspicious"}
    msg = _build_message(base_signals)
    assert "CUSTOM CHECKS" in msg
    assert "extra_signal" in msg


# ---------------------------------------------------------------------------
# classify — new_dependency_count passthrough
# ---------------------------------------------------------------------------


async def test_classify_llm_passes_new_dependency_count_through(base_signals, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    base_signals.diff.new_dependency_count = 3
    mock_client = _make_llm_mock(
        {
            "classification": "yellow",
            "confidence": 0.7,
            "reasoning": "New dep.",
            "flags": ["new dep"],
            "new_dependency_count": 0,
        }
    )
    env = ActivityEnvironment()
    with patch("classifiers.anthropic.anthropic.AsyncAnthropic", return_value=mock_client):
        verdict = await env.run(classify, base_signals)
    assert verdict.new_dependency_count == 3


# ---------------------------------------------------------------------------
# OpenAI classifier
# ---------------------------------------------------------------------------


async def test_openai_classifier_no_model_falls_back(base_signals, monkeypatch):
    from classifiers import OpenAIClassifier

    monkeypatch.delenv("OPENAI_MODEL", raising=False)
    verdict = await OpenAIClassifier().classify(base_signals)
    assert verdict.classification in ("green", "yellow", "red")
    assert "[rule-based]" in verdict.reasoning


@respx.mock
async def test_openai_classifier_success(base_signals, monkeypatch):
    import json
    from classifiers import OpenAIClassifier

    monkeypatch.setenv("OPENAI_MODEL", "gpt-4o")
    tool_call = {
        "function": {
            "arguments": json.dumps(
                {"classification": "green", "confidence": 0.9, "reasoning": "OK.", "flags": []}
            )
        }
    }
    respx.post("https://api.openai.com/v1/chat/completions").mock(
        return_value=httpx.Response(
            200,
            json={"choices": [{"message": {"tool_calls": [tool_call]}}]},
        )
    )
    verdict = await OpenAIClassifier().classify(base_signals)
    assert verdict.classification == "green"


@respx.mock
async def test_openai_classifier_exception_falls_back(base_signals, monkeypatch):
    from classifiers import OpenAIClassifier

    monkeypatch.setenv("OPENAI_MODEL", "gpt-4o")
    respx.post("https://api.openai.com/v1/chat/completions").mock(
        side_effect=httpx.ConnectError("openai down")
    )
    verdict = await OpenAIClassifier().classify(base_signals)
    assert verdict.classification in ("green", "yellow", "red")
    assert "[rule-based]" in verdict.reasoning


# ---------------------------------------------------------------------------
# Ollama classifier
# ---------------------------------------------------------------------------


@respx.mock
async def test_ollama_classifier_success(base_signals, monkeypatch):
    import json
    from classifiers import OllamaClassifier

    monkeypatch.setenv("OLLAMA_MODEL", "llama3")
    respx.post("http://localhost:11434/api/chat").mock(
        return_value=httpx.Response(
            200,
            json={
                "message": {
                    "content": json.dumps(
                        {
                            "classification": "green",
                            "confidence": 0.85,
                            "reasoning": "OK.",
                            "flags": [],
                        }
                    )
                }
            },
        )
    )
    verdict = await OllamaClassifier().classify(base_signals)
    assert verdict.classification == "green"


@respx.mock
async def test_ollama_classifier_exception_falls_back(base_signals, monkeypatch):
    from classifiers import OllamaClassifier

    monkeypatch.setenv("OLLAMA_MODEL", "llama3")
    respx.post("http://localhost:11434/api/chat").mock(
        side_effect=httpx.ConnectError("ollama down")
    )
    verdict = await OllamaClassifier().classify(base_signals)
    assert verdict.classification in ("green", "yellow", "red")
    assert "[rule-based]" in verdict.reasoning


# ---------------------------------------------------------------------------
# get_classifier — entry point exception and explicit built-in name
# ---------------------------------------------------------------------------


def test_get_classifier_entry_point_exception_falls_through(monkeypatch):
    from classifiers import get_classifier, RuleBasedClassifier
    from unittest.mock import patch, MagicMock

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("CLASSIFIER", "rule_based")

    bad_ep = MagicMock()
    bad_ep.name = "rule_based"
    bad_ep.load.side_effect = ImportError("broken")

    with patch("classifiers.entry_points", return_value=[bad_ep]):
        clf = get_classifier()

    assert isinstance(clf, RuleBasedClassifier)


# ---------------------------------------------------------------------------
# helpers/cache.py — TTL expiry and __len__
# ---------------------------------------------------------------------------


def test_cache_ttl_expiry():
    import time
    from helpers.cache import ActivityCache

    cache = ActivityCache(ttl_seconds=0.001)
    cache.set(("key",), "value")
    time.sleep(0.05)
    assert cache.get(("key",)) is None


def test_cache_len():
    from helpers.cache import ActivityCache

    cache = ActivityCache()
    assert len(cache) == 0
    cache.set(("a",), 1)
    assert len(cache) == 1
    cache.set(("b",), 2)
    assert len(cache) == 2
