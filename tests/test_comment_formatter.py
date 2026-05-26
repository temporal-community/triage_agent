import pytest
from helpers.comment_formatter import format_comment, _sanitize_reasoning
from models import (
    PRContext,
    PackageChecks,
    Verdict,
    AttestationChecks,
    DepsDevChecks,
    MaintainerChecks,
    MetadataChecks,
    OSVChecks,
    PackageDiffChecks,
    ReleaseAgeChecks,
    ReleaseChecks,
    ScorecardChecks,
    SocketChecks,
    VersionLineageChecks,
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
        attestation=AttestationChecks(),
        release=ReleaseChecks(),
        version_lineage=VersionLineageChecks(),
        deps_dev=DepsDevChecks(),
        scorecard=ScorecardChecks(),
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
    assert "and 2 more checks" in out
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
    assert "and 1 more check" in out
    assert "and 1 more checks" not in out


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
    assert "| Check |" not in out


def test_signals_table_header_present(pr, green_verdict, signals):
    out = format_comment(pr, green_verdict, signals)
    assert "| Check |" in out


def test_signals_all_checks_present(pr, green_verdict, signals):
    out = format_comment(pr, green_verdict, signals)
    for label in (
        "Downloads",
        "Socket score",
        "Vulnerabilities",
        "Diff scan",
        "Maintainer",
        "Release age",
        "Attestation",
        "Release notes",
        "Version lineage",
        "Deprecation",
        "OpenSSF Scorecard",
    ):
        assert label in out, f"missing check row: {label}"


def test_signals_downloads_na_when_none(pr, green_verdict, signals):
    signals.metadata.weekly_downloads = None
    out = format_comment(pr, green_verdict, signals)
    assert "N/A — no download data for this ecosystem" in out


def test_signals_downloads_shows_count(pr, green_verdict, signals):
    out = format_comment(pr, green_verdict, signals)
    assert "5,000,000 weekly downloads" in out


def test_signals_socket_ok_above_70(pr, green_verdict, signals):
    signals.socket.socket_score = 85
    out = format_comment(pr, green_verdict, signals)
    assert "✅" in out
    assert "score 85/100" in out


def test_signals_socket_warn_between_40_and_70(pr, green_verdict, signals):
    signals.socket.socket_score = 55
    out = format_comment(pr, green_verdict, signals)
    assert "⚠️" in out
    assert "score 55/100" in out


def test_signals_socket_bad_below_40(pr, green_verdict, signals):
    signals.socket.socket_score = 20
    out = format_comment(pr, green_verdict, signals)
    assert "🚨" in out
    assert "score 20/100" in out


def test_signals_socket_na_when_none(pr, green_verdict, signals):
    signals.socket.socket_score = None
    out = format_comment(pr, green_verdict, signals)
    assert "Socket score" in out
    assert "N/A" in out


def test_signals_osv_bad_when_vulns(pr, green_verdict, signals):
    signals.osv.osv_vulnerabilities = ["CVE-2024-0001", "CVE-2024-0002"]
    out = format_comment(pr, green_verdict, signals)
    assert "🚨" in out
    assert "2 known vulnerabilities" in out


def test_signals_osv_ok_when_clean(pr, green_verdict, signals):
    out = format_comment(pr, green_verdict, signals)
    assert "no known vulnerabilities" in out


def test_signals_diff_bad_when_install_script(pr, green_verdict, signals):
    signals.diff.install_script_added = True
    out = format_comment(pr, green_verdict, signals)
    assert "🚨" in out
    assert "install script added" in out


def test_signals_maintainer_warn_when_changed(pr, green_verdict, signals):
    signals.maintainer.maintainer_changed = True
    out = format_comment(pr, green_verdict, signals)
    assert "⚠️" in out
    assert "maintainer changed" in out


def test_signals_age_ok_above_168h(pr, green_verdict, signals):
    signals.age.release_age_hours = 200.0
    out = format_comment(pr, green_verdict, signals)
    assert "released 8 days ago" in out


def test_signals_age_warn_below_168h(pr, green_verdict, signals):
    signals.age.release_age_hours = 48.0
    out = format_comment(pr, green_verdict, signals)
    assert "⚠️" in out
    assert "released 2 days ago" in out


def test_signals_age_months(pr, green_verdict, signals):
    signals.age.release_age_hours = 3277.0  # 136 days → 4 months 16 days
    out = format_comment(pr, green_verdict, signals)
    assert "released 4 months 16 days ago" in out


def test_signals_age_hours_when_under_24h(pr, green_verdict, signals):
    signals.age.release_age_hours = 10.0
    out = format_comment(pr, green_verdict, signals)
    assert "released 10h ago" in out


def test_signals_age_na_when_unknown(pr, green_verdict, signals):
    signals.age.release_age_hours = None
    out = format_comment(pr, green_verdict, signals)
    assert "release age unknown" in out


def test_signals_scorecard_ok_above_7(pr, green_verdict, signals):
    signals.scorecard.scorecard_score = 8.5
    out = format_comment(pr, green_verdict, signals)
    assert "score 8.5/10" in out


def test_signals_scorecard_bad_below_4(pr, green_verdict, signals):
    signals.scorecard.scorecard_score = 2.0
    out = format_comment(pr, green_verdict, signals)
    assert "🚨" in out
    assert "score 2.0/10" in out


def test_signals_scorecard_na_when_none(pr, green_verdict, signals):
    out = format_comment(pr, green_verdict, signals)
    assert "N/A — not in Scorecard database" in out


def test_signals_deprecated_bad(pr, green_verdict, signals):
    signals.deps_dev.is_deprecated = True
    signals.deps_dev.deprecated_reason = "use requests2 instead"
    out = format_comment(pr, green_verdict, signals)
    assert "🚨" in out
    assert "deprecated: use requests2 instead" in out


# --- URL generation ---


def test_footer_contains_repo_link(pr, green_verdict):
    out = format_comment(pr, green_verdict)
    assert "https://github.com/temporal-community/dependency-scout" in out
    assert "Dependency Scout" in out


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
