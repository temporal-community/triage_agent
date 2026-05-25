import pytest
from helpers.comment_formatter import format_comment, _sanitize_reasoning
from models import (
    PRContext,
    PackageChecks,
    Verdict,
    MetadataChecks,
    SocketChecks,
    OSVChecks,
    PackageDiffChecks,
    ReleaseAgeChecks,
    MaintainerChecks,
)


# --- _sanitize_reasoning ---


def test_sanitize_strips_markdown_links():
    assert _sanitize_reasoning("see [evil text](https://evil.com)") == "see evil text"


def test_sanitize_strips_bare_urls():
    assert _sanitize_reasoning("visit https://evil.com now") == "visit [url removed] now"


def test_sanitize_strips_multiple_links():
    text = "[a](http://x.com) and [b](http://y.com)"
    assert _sanitize_reasoning(text) == "a and b"


def test_sanitize_truncates_at_500():
    long_text = "a" * 600
    result = _sanitize_reasoning(long_text)
    assert len(result) == 501  # 500 chars + "…"
    assert result.endswith("…")


def test_sanitize_passthrough_clean():
    text = "Package looks safe. Maintainer is stable."
    assert _sanitize_reasoning(text) == text


# --- format_comment badges ---


@pytest.fixture
def pr():
    return PRContext(
        repo="owner/repo",
        pr_number=42,
        pr_author="dependabot[bot]",
        installation_id=123,
        ecosystem="pip",
        package_name="requests",
        old_version="2.31.0",
        new_version="2.32.0",
        head_sha="abc123",
    )


@pytest.fixture
def green_verdict():
    return Verdict(
        classification="green",
        confidence=0.95,
        reasoning="Routine patch bump from trusted maintainer.",
        flags=[],
    )


@pytest.fixture
def signals():
    return PackageChecks(
        ecosystem="pip",
        package_name="requests",
        old_version="2.31.0",
        new_version="2.32.0",
        metadata=MetadataChecks(weekly_downloads=5_000_000, is_major_bump=False),
        socket=SocketChecks(socket_score=85, socket_alerts=[]),
        osv=OSVChecks(osv_vulnerabilities=[]),
        diff=PackageDiffChecks(diff_summary="Minor changes", diff_size_bytes=1024),
        age=ReleaseAgeChecks(release_age_hours=200.0),
        maintainer=MaintainerChecks(maintainer_changed=False),
    )


def test_green_badge(pr, green_verdict):
    out = format_comment(pr, green_verdict)
    assert "🟢 GREEN" in out


def test_yellow_badge(pr):
    verdict = Verdict(classification="yellow", confidence=0.7, reasoning="Uncertain.", flags=[])
    out = format_comment(pr, verdict)
    assert "🟡 YELLOW" in out


def test_red_badge(pr):
    verdict = Verdict(classification="red", confidence=0.9, reasoning="Suspicious.", flags=[])
    out = format_comment(pr, verdict)
    assert "🔴 RED" in out


def test_unknown_classification_falls_back_to_upper(pr):
    verdict = Verdict(classification="green", confidence=1.0, reasoning="ok", flags=[])
    verdict.classification = "unknown"  # type: ignore[assignment]
    out = format_comment(pr, verdict)
    assert "UNKNOWN" in out


# --- confidence formatting ---


def test_confidence_rendered_as_percentage(pr, green_verdict):
    out = format_comment(pr, green_verdict)
    assert "**Confidence:** 95%" in out


# --- flags section ---


def test_no_flags_section_when_empty(pr, green_verdict):
    out = format_comment(pr, green_verdict)
    assert "**Flags:**" not in out


def test_flags_rendered_when_present(pr):
    verdict = Verdict(
        classification="yellow",
        confidence=0.6,
        reasoning="Meh.",
        flags=["New maintainer account", "Released <24h ago"],
    )
    out = format_comment(pr, verdict)
    assert "**Flags:**" in out
    assert "- New maintainer account" in out
    assert "- Released <24h ago" in out


def test_yellow_many_flags_folds_tail(pr):
    flags = ["flag one", "flag two", "flag three", "flag four", "flag five"]
    verdict = Verdict(
        classification="yellow", confidence=0.6, reasoning="Several issues.", flags=flags
    )
    out = format_comment(pr, verdict)
    assert "- flag one" in out
    assert "- flag two" in out
    assert "- flag three" in out
    assert "<details>" in out
    assert "and 2 more signals" in out
    assert "- flag four" in out
    assert "- flag five" in out


def test_yellow_three_flags_not_folded(pr):
    flags = ["a", "b", "c"]
    verdict = Verdict(
        classification="yellow", confidence=0.6, reasoning="Three issues.", flags=flags
    )
    out = format_comment(pr, verdict)
    assert "<details>" not in out
    assert "- a" in out
    assert "- c" in out


def test_red_many_flags_never_folded(pr):
    flags = [f"critical issue {i}" for i in range(6)]
    verdict = Verdict(classification="red", confidence=0.95, reasoning="Bad.", flags=flags)
    out = format_comment(pr, verdict)
    assert "<details>" not in out
    for flag in flags:
        assert f"- {flag}" in out


def test_fold_uses_singular_signal_noun(pr):
    flags = ["flag one", "flag two", "flag three", "flag four"]
    verdict = Verdict(classification="yellow", confidence=0.6, reasoning="Issues.", flags=flags)
    out = format_comment(pr, verdict)
    assert "and 1 more signal" in out
    assert "and 1 more signals" not in out


def test_flags_are_sanitized(pr):
    verdict = Verdict(
        classification="red",
        confidence=0.9,
        reasoning="Bad.",
        flags=["See [details](https://attacker.com)"],
    )
    out = format_comment(pr, verdict)
    assert "https://attacker.com" not in out
    assert "- See details" in out


# --- signals table ---


def test_no_signals_table_without_signals(pr, green_verdict):
    out = format_comment(pr, green_verdict)
    assert "| Signal |" not in out


def test_signals_table_present_with_signals(pr, green_verdict, signals):
    out = format_comment(pr, green_verdict, signals)
    assert "| Signal | Value |" in out


def test_signals_release_age_rendered(pr, green_verdict, signals):
    out = format_comment(pr, green_verdict, signals)
    assert "| Release age | 200h |" in out


def test_signals_release_age_unknown_when_none(pr, green_verdict, signals):
    signals.age.release_age_hours = None
    out = format_comment(pr, green_verdict, signals)
    assert "| Release age | unknown |" in out


def test_signals_weekly_downloads_formatted(pr, green_verdict, signals):
    out = format_comment(pr, green_verdict, signals)
    assert "| Weekly downloads | 5,000,000 |" in out


def test_signals_weekly_downloads_unknown_when_none(pr, green_verdict, signals):
    signals.metadata.weekly_downloads = None
    out = format_comment(pr, green_verdict, signals)
    assert "| Weekly downloads | unknown |" in out


def test_signals_socket_score_rendered(pr, green_verdict, signals):
    out = format_comment(pr, green_verdict, signals)
    assert "| Socket score | 85/100 |" in out


def test_signals_socket_score_unavailable_when_none(pr, green_verdict, signals):
    signals.socket.socket_score = None
    out = format_comment(pr, green_verdict, signals)
    assert "| Socket score | unavailable |" in out


def test_signals_cve_count(pr, green_verdict, signals):
    signals.osv.osv_vulnerabilities = ["CVE-2024-0001", "CVE-2024-0002"]
    out = format_comment(pr, green_verdict, signals)
    assert "| CVEs | 2 |" in out


def test_signals_maintainer_changed_yes(pr, green_verdict, signals):
    signals.maintainer.maintainer_changed = True
    out = format_comment(pr, green_verdict, signals)
    assert "| Maintainer changed | yes |" in out


def test_signals_maintainer_changed_no(pr, green_verdict, signals):
    out = format_comment(pr, green_verdict, signals)
    assert "| Maintainer changed | no |" in out


def test_signals_major_bump_yes(pr, green_verdict, signals):
    signals.metadata.is_major_bump = True
    out = format_comment(pr, green_verdict, signals)
    assert "| Major bump | yes |" in out


def test_signals_diff_size_formatted(pr, green_verdict, signals):
    signals.diff.diff_size_bytes = 1_234_567
    out = format_comment(pr, green_verdict, signals)
    assert "| Diff size | 1,234,567 bytes |" in out


# --- URL generation ---


def test_workflow_url_uses_env_vars(pr, green_verdict, monkeypatch):
    monkeypatch.setenv("TEMPORAL_UI_BASE_URL", "https://cloud.temporal.io")
    monkeypatch.setenv("TEMPORAL_NAMESPACE", "acme-prod")
    out = format_comment(pr, green_verdict)
    assert (
        "https://cloud.temporal.io/namespaces/acme-prod/workflows/triage-pip-requests-2.32.0" in out
    )


def test_workflow_url_defaults(pr, green_verdict, monkeypatch):
    monkeypatch.delenv("TEMPORAL_UI_BASE_URL", raising=False)
    monkeypatch.delenv("TEMPORAL_NAMESPACE", raising=False)
    out = format_comment(pr, green_verdict)
    assert "http://localhost:8233/namespaces/default/workflows/triage-pip-requests-2.32.0" in out


def test_config_url_points_to_repo(pr, green_verdict):
    out = format_comment(pr, green_verdict)
    assert "https://github.com/owner/repo/blob/HEAD/.github/triage-agent.yml" in out


# --- reasoning is sanitized in output ---


def test_reasoning_links_stripped_in_output(pr):
    verdict = Verdict(
        classification="green",
        confidence=0.8,
        reasoning="Read [this](https://attacker.com) for details.",
        flags=[],
    )
    out = format_comment(pr, verdict)
    assert "https://attacker.com" not in out
    assert "Read this for details." in out
