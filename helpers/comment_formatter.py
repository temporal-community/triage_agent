import json
import re
from models import PRContext, PackageChecks, Verdict


_MAX_REASONING_LEN = 2000  # hard safety cap on sanitized text
_PREVIEW_LEN = 250  # chars shown in the blockquote before the collapsible expander


def _sanitize_reasoning(text: str) -> str:
    """Strip Markdown formatting and cap length — reasoning is LLM output influenced by
    attacker-controlled diff content and must not render arbitrary links or formatting in PR comments."""
    # Replace [text](url) with just the text
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    # Strip bare URLs
    text = re.sub(r"https?://\S+", "[url removed]", text)
    # Strip bold/italic — LLM may use field names like **ci_workflow_changed_days_ago**
    # which get cut off mid-span by truncation and break the comment's markdown
    text = re.sub(r"\*\*([^*]*)\*\*", r"\1", text)
    text = re.sub(r"\*([^*]*)\*", r"\1", text)
    # Collapse multi-paragraph reasoning to a single paragraph — the blockquote
    # renderer only styles the first paragraph, so numbered lists look broken
    text = re.sub(r"\n+", " ", text).strip()
    if len(text) > _MAX_REASONING_LEN:
        truncated = text[:_MAX_REASONING_LEN]
        last_space = truncated.rfind(" ")
        text = (truncated[:last_space] if last_space > _MAX_REASONING_LEN // 2 else truncated) + "…"
    return text


def _reasoning_block(text: str) -> list[str]:
    """Return blockquote lines for reasoning, with a collapsible expander when long."""
    if len(text) <= _PREVIEW_LEN:
        return [f"> {text}"]
    preview = text[:_PREVIEW_LEN]
    last_space = preview.rfind(" ")
    preview = (preview[:last_space] if last_space > _PREVIEW_LEN // 2 else preview) + "…"
    return [
        f"> {preview}",
        "",
        "<details><summary>Full reasoning</summary>",
        "",
        f"> {text}",
        "",
        "</details>",
    ]


def _format_age(hours: float) -> str:
    days = int(hours // 24)
    if days == 0:
        return f"{int(hours)}h"
    if days < 14:
        return f"{days} day{'s' if days != 1 else ''}"
    if days < 60:
        w, d = divmod(days, 7)
        s = f"{w} week{'s' if w != 1 else ''}"
        return s + (f" {d} day{'s' if d != 1 else ''}" if d else "")
    if days < 365:
        mo, d = divmod(days, 30)
        s = f"{mo} month{'s' if mo != 1 else ''}"
        return s + (f" {d} day{'s' if d != 1 else ''}" if d else "")
    yr, rem = divmod(days, 365)
    mo = rem // 30
    s = f"{yr} year{'s' if yr != 1 else ''}"
    return s + (f" {mo} month{'s' if mo != 1 else ''}" if mo else "")


_STATUS_ICON = {"ok": "✅", "warn": "⚠️", "bad": "🚨", "na": "—"}

_CHECK_LABEL = {
    "metadata": "Downloads",
    "socket": "[Socket score](https://socket.dev)",
    "osv": "[Vulnerabilities](https://osv.dev)",
    "install_script": "Install script",
    "network_calls": "Network calls",
    "new_deps": "New dependencies",
    "diff_integrity": "Diff integrity",
    "maintainer": "Maintainer",
    "age": "Release age",
    "ci_workflow": "CI workflow",
    "tag_signing": "Tag signing",
    "publisher": "Publisher",
    "attestation": "[Attestation](https://slsa.dev)",
    "release_notes": "Release notes",
    "version_lineage": "Version lineage",
    "deps_dev": "[Deprecation](https://deps.dev)",
    "scorecard": "[OpenSSF Scorecard](https://scorecard.dev)",
}


def _signals_table(signals: PackageChecks) -> list[str]:
    rows: list[tuple[str, str, str]] = []

    def _row(name: str, status: str, text: str) -> None:
        rows.append((_CHECK_LABEL[name], _STATUS_ICON[status], text))

    # Package health
    m = signals.metadata
    if m.weekly_downloads is not None:
        _row("metadata", "na", f"{m.weekly_downloads:,} weekly downloads")
    else:
        _row("metadata", "na", "N/A — no download data for this ecosystem")

    if signals.socket.socket_score is not None:
        s = signals.socket.socket_score
        alert_note = (
            f"; {len(signals.socket.socket_alerts)} alert(s)"
            if signals.socket.socket_alerts
            else ""
        )
        _row(
            "socket",
            "ok" if s >= 70 else ("warn" if s >= 40 else "bad"),
            f"score {s}/100{alert_note}",
        )
    else:
        _row("socket", "na", "N/A — no data")

    if signals.osv.osv_vulnerabilities:
        _row("osv", "bad", f"{len(signals.osv.osv_vulnerabilities)} known vulnerabilities")
    else:
        _row("osv", "ok", "no known vulnerabilities")

    # Diff analysis
    d = signals.diff
    if d.install_script_added:
        _row("install_script", "bad", "new install hook added")
    elif d.install_script_changed:
        _row("install_script", "warn", "install hook modified")
    else:
        _row("install_script", "ok", "none")

    if d.network_calls_in_lib:
        _row("network_calls", "bad", "new outbound network calls in library code")
    else:
        _row("network_calls", "ok", "none detected")

    n = d.new_dependency_count
    if n == 0:
        _row("new_deps", "ok", "none added")
    elif n < 5:
        _row("new_deps", "ok", f"{n} added")
    else:
        _row("new_deps", "warn", f"{n} added")

    integrity_issues = []
    if d.artifact_source_mismatch:
        integrity_issues.append("source/archive mismatch")
    if d.persistence_mechanism_added:
        integrity_issues.append("persistence mechanism")
    if d.worm_propagation_pattern:
        integrity_issues.append("worm propagation")
    if d.binary_data_added:
        integrity_issues.append("binary data in non-binary file")
    if d.obfuscated_code:
        integrity_issues.append("obfuscated code")
    if d.git_url_dependency_added:
        integrity_issues.append("git URL dependency")
    if d.lockfile_integrity_downgraded:
        integrity_issues.append("lockfile integrity downgraded")
    if integrity_issues:
        _row("diff_integrity", "bad", "; ".join(integrity_issues))
    else:
        _row("diff_integrity", "ok", "clean")

    # Maintainer
    if signals.maintainer.maintainer_changed:
        age = signals.maintainer.new_maintainer_account_age_days
        if age is not None:
            _row("maintainer", "warn", f"changed — new account {age} days old")
        else:
            _row("maintainer", "warn", "changed")
    else:
        _row("maintainer", "ok", "no changes detected")

    # Release signals
    h = signals.age.release_age_hours
    if h is not None:
        _row("age", "warn" if h < 168 else "ok", f"released {_format_age(h)} ago")
    else:
        _row("age", "na", "release age unknown")

    ci = signals.release.ci_workflow_changed_days_ago
    if ci is not None:
        _row("ci_workflow", "warn", f"changed {ci} day{'s' if ci != 1 else ''} ago")
    else:
        _row("ci_workflow", "ok", "no recent changes")

    if signals.release.tag_was_previously_signed:
        _row("tag_signing", "warn", "signing dropped — old version had a verified tag")
    elif signals.release.tag_signature_verified is True:
        _row("tag_signing", "ok", "verified")
    elif signals.release.tag_signature_verified is False:
        _row("tag_signing", "warn", "unverified tag")
    else:
        _row("tag_signing", "na", "no annotated tag")

    # Attestation / publisher
    att = signals.attestation
    if att.publisher_changed:
        old = f" (was {att.old_publisher_repo})" if att.old_publisher_repo else ""
        age_note = (
            f"; account {att.publisher_account_age_days}d old"
            if att.publisher_account_age_days is not None
            else ""
        )
        _row("publisher", "warn", f"changed{old}{age_note}")
    elif att.publisher_repo:
        if att.publisher_account_age_days is not None and att.publisher_account_age_days < 90:
            _row(
                "publisher",
                "warn",
                f"{att.publisher_repo} ({att.publisher_account_age_days}d old account)",
            )
        else:
            _row("publisher", "ok", att.publisher_repo)
    else:
        _row("publisher", "na", "N/A — no attestation")

    if att.has_attestation:
        _row("attestation", "ok", "build provenance verified")
    else:
        _row("attestation", "na", "N/A — no build provenance")

    if signals.release.github_release_exists:
        _row("release_notes", "ok", "GitHub release found")
    else:
        _row("release_notes", "na", "N/A — no GitHub release")

    # Version & registry
    if signals.version_lineage.stale_version_line:
        _row("version_lineage", "warn", "stale version line")
    else:
        _row("version_lineage", "ok", "on latest version line")

    if signals.deps_dev.is_deprecated:
        reason = signals.deps_dev.deprecated_reason or "yes"
        _row("deps_dev", "bad", f"deprecated: {reason}")
    else:
        _row("deps_dev", "ok", "not deprecated")

    if signals.scorecard.scorecard_score is not None:
        sc = signals.scorecard.scorecard_score
        sub_notes = []
        if signals.scorecard.scorecard_dangerous_workflow == 0:
            sub_notes.append("dangerous workflow")
        if signals.scorecard.scorecard_maintained == 0:
            sub_notes.append("unmaintained")
        sub = f"; {', '.join(sub_notes)}" if sub_notes else ""
        _row(
            "scorecard",
            "ok" if sc >= 7 else ("warn" if sc >= 4 else "bad"),
            f"score {sc:.1f}/10{sub}",
        )
    else:
        _row("scorecard", "na", "N/A — not in Scorecard database")

    lines = ["| Check | | Detail |", "|-------|:---:|--------|"]
    for label, icon, text in rows:
        lines.append(f"| {label} | {icon} | {text} |")
    return lines


_BADGE = {
    "green": "🟢 GREEN",
    "yellow": "🟡 YELLOW",
    "red": "🔴 RED",
}

_MERGE_REC_BADGE = {
    "merge": "✅ Merge recommended",
    "hold": "⏸️ Hold for review",
}


def format_comment(pr: PRContext, verdict: Verdict, signals: PackageChecks | None = None) -> str:
    badge = _BADGE.get(verdict.classification, verdict.classification.upper())

    lines = [
        f"## Dependency Scout — {badge}",
        "",
        f"**Package:** `{pr.package_name}` {pr.old_version} → {pr.new_version}  ",
        f"**Confidence:** {verdict.confidence:.0%}",
    ]

    if verdict.merge_recommendation is not None:
        rec_badge = _MERGE_REC_BADGE.get(verdict.merge_recommendation, verdict.merge_recommendation)
        lines += [
            f"**Merge recommendation:** {rec_badge}",
        ]

    lines += [
        "",
        *_reasoning_block(_sanitize_reasoning(verdict.reasoning)),
        "",
    ]

    if verdict.flags:
        lines += [f"**Flags:** {' · '.join(verdict.flags)}", ""]

    if signals:
        lines += _signals_table(signals) + [""]

    lines += [
        "---",
        "_[Dependency Scout](https://github.com/temporal-community/dependency-scout) — "
        "automated supply-chain vetting for Dependabot/Renovate PRs_",
        "",
        "<!-- dependency-scout-data "
        + json.dumps(
            {
                "classification": verdict.classification,
                "confidence": round(verdict.confidence, 4),
                "merge_recommendation": verdict.merge_recommendation,
                "flags": verdict.flags,
                "package": pr.package_name,
                "from_version": pr.old_version,
                "to_version": pr.new_version,
            }
        )
        + " -->",
    ]

    return "\n".join(lines)
