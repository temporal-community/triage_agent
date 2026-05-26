import pytest
from helpers.comment_formatter import format_comment, _sanitize_reasoning, _reasoning_block
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


def test_sanitize_truncates_at_2000():
    long_text = "a" * 2100
    result = _sanitize_reasoning(long_text)
    assert len(result) == 2001  # 2000 chars + "…"
    assert result.endswith("…")


def test_reasoning_block_short_returns_single_blockquote():
    text = "Short reasoning."
    block = _reasoning_block(text)
    assert block == ["> Short reasoning."]


def test_reasoning_block_long_includes_details():
    text = "word " * 60  # well over 250 chars
    text = text.strip()
    block = _reasoning_block(text)
    full_block = "\n".join(block)
    assert "<details>" in full_block
    assert "<summary>Full reasoning</summary>" in full_block
    assert "</details>" in full_block
    # preview line is first
    assert block[0].startswith("> ")
    assert block[0].endswith("…")
    # full text appears inside details
    assert f"> {text}" in block


def test_reasoning_block_preview_ends_at_word_boundary():
    # 250 chars of "word " repeated, so word boundary is clean
    text = ("hello world " * 25).strip()
    block = _reasoning_block(text)
    preview = block[0][2:]  # strip "> "
    assert preview.endswith("…")
    assert not preview[:-1].endswith(" ")


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


# --- package header ---


def test_package_header_present(pr, green_verdict):
    out = format_comment(pr, green_verdict)
    assert "**Package:** `requests` 2.31.0 → 2.32.0" in out


# --- flags section ---


def test_flags_shown_when_present(pr):
    verdict = Verdict(
        classification="yellow",
        confidence=0.6,
        reasoning="Meh.",
        flags=["major version bump", "release age 2 days"],
    )
    out = format_comment(pr, verdict)
    assert "**Flags:** major version bump · release age 2 days" in out


def test_flags_hidden_when_empty(pr, green_verdict):
    out = format_comment(pr, green_verdict)
    assert "**Flags:**" not in out


# --- machine-readable data block ---


def test_data_block_present(pr, green_verdict):
    out = format_comment(pr, green_verdict)
    assert "<!-- dependency-scout-data " in out
    assert " -->" in out


def test_data_block_parses_as_json(pr):
    import json

    verdict = Verdict(
        classification="yellow",
        confidence=0.75,
        reasoning="Uncertain.",
        flags=["major version bump"],
        merge_recommendation="hold",
    )
    out = format_comment(pr, verdict)
    raw = out.split("<!-- dependency-scout-data ")[1].split(" -->")[0]
    data = json.loads(raw)
    assert data["classification"] == "yellow"
    assert data["confidence"] == 0.75
    assert data["merge_recommendation"] == "hold"
    assert data["flags"] == ["major version bump"]
    assert data["package"] == "requests"
    assert data["from_version"] == "2.31.0"
    assert data["to_version"] == "2.32.0"


def test_data_block_null_merge_recommendation(pr, green_verdict):
    import json

    out = format_comment(pr, green_verdict)
    raw = out.split("<!-- dependency-scout-data ")[1].split(" -->")[0]
    data = json.loads(raw)
    assert data["merge_recommendation"] is None


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
        "Install script",
        "Network calls",
        "New dependencies",
        "Diff integrity",
        "Maintainer",
        "Release age",
        "CI workflow",
        "Tag signing",
        "Publisher",
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


def test_signals_install_script_bad_when_added(pr, green_verdict, signals):
    signals.diff.install_script_added = True
    out = format_comment(pr, green_verdict, signals)
    assert "🚨" in out
    assert "new install hook added" in out


def test_signals_install_script_warn_when_changed(pr, green_verdict, signals):
    signals.diff.install_script_changed = True
    out = format_comment(pr, green_verdict, signals)
    assert "⚠️" in out
    assert "install hook modified" in out


def test_signals_network_calls_bad(pr, green_verdict, signals):
    signals.diff.network_calls_in_lib = True
    out = format_comment(pr, green_verdict, signals)
    assert "🚨" in out
    assert "new outbound network calls in library code" in out


def test_signals_new_deps_warn_above_threshold(pr, green_verdict, signals):
    signals.diff.new_dependency_count = 6
    out = format_comment(pr, green_verdict, signals)
    assert "⚠️" in out
    assert "6 added" in out


def test_signals_diff_integrity_bad(pr, green_verdict, signals):
    signals.diff.obfuscated_code = True
    out = format_comment(pr, green_verdict, signals)
    assert "🚨" in out
    assert "obfuscated code" in out


def test_signals_maintainer_warn_when_changed(pr, green_verdict, signals):
    signals.maintainer.maintainer_changed = True
    out = format_comment(pr, green_verdict, signals)
    assert "⚠️" in out
    assert "changed" in out


def test_signals_maintainer_shows_account_age(pr, green_verdict, signals):
    signals.maintainer.maintainer_changed = True
    signals.maintainer.new_maintainer_account_age_days = 45
    out = format_comment(pr, green_verdict, signals)
    assert "45 days old" in out


def test_signals_ci_workflow_warn_when_changed(pr, green_verdict, signals):
    signals.release.ci_workflow_changed_days_ago = 3
    out = format_comment(pr, green_verdict, signals)
    assert "⚠️" in out
    assert "changed 3 days ago" in out


def test_signals_tag_signing_warn_when_dropped(pr, green_verdict, signals):
    signals.release.tag_was_previously_signed = True
    out = format_comment(pr, green_verdict, signals)
    assert "⚠️" in out
    assert "signing dropped" in out


def test_signals_publisher_warn_when_changed(pr, green_verdict, signals):
    signals.attestation.publisher_changed = True
    signals.attestation.old_publisher_repo = "old-org/repo"
    out = format_comment(pr, green_verdict, signals)
    assert "⚠️" in out
    assert "old-org/repo" in out


def test_signals_scorecard_shows_dangerous_workflow(pr, green_verdict, signals):
    signals.scorecard.scorecard_score = 5.0
    signals.scorecard.scorecard_dangerous_workflow = 0
    out = format_comment(pr, green_verdict, signals)
    assert "dangerous workflow" in out


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


def test_reasoning_short_no_details_block(pr):
    verdict = Verdict(
        classification="green",
        confidence=0.9,
        reasoning="Short and sweet.",
        flags=[],
    )
    out = format_comment(pr, verdict)
    assert "<details>" not in out
    assert "> Short and sweet." in out


def test_reasoning_long_shows_collapsible(pr):
    long_reasoning = "This is a long sentence explaining the risk. " * 10
    verdict = Verdict(
        classification="yellow",
        confidence=0.7,
        reasoning=long_reasoning,
        flags=[],
    )
    out = format_comment(pr, verdict)
    assert "<details>" in out
    assert "<summary>Full reasoning</summary>" in out
    assert "</details>" in out
    # preview blockquote is present and truncated
    lines = out.splitlines()
    blockquote_lines = [ln for ln in lines if ln.startswith("> ")]
    assert any(ln.endswith("…") for ln in blockquote_lines)
