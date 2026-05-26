import re
from models import PRContext, PackageChecks, Verdict


_MAX_REASONING_LEN = 500


def _sanitize_reasoning(text: str) -> str:
    """Strip Markdown links and cap length — reasoning is LLM output influenced by
    attacker-controlled diff content and must not render arbitrary links in PR comments."""
    # Replace [text](url) with just the text
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    # Strip bare URLs
    text = re.sub(r"https?://\S+", "[url removed]", text)
    if len(text) > _MAX_REASONING_LEN:
        text = text[:_MAX_REASONING_LEN] + "…"
    return text


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
    "socket": "Socket score",
    "osv": "Vulnerabilities",
    "diff": "Diff scan",
    "maintainer": "Maintainer",
    "age": "Release age",
    "attestation": "Attestation",
    "release_notes": "Release notes",
    "version_lineage": "Version lineage",
    "deps_dev": "Deprecation",
    "scorecard": "OpenSSF Scorecard",
}


def _signals_table(signals: PackageChecks) -> list[str]:
    rows: list[tuple[str, str, str]] = []

    def _row(name: str, status: str, text: str) -> None:
        rows.append((_CHECK_LABEL[name], _STATUS_ICON[status], text))

    m = signals.metadata
    if m.weekly_downloads is not None:
        _row("metadata", "na", f"{m.weekly_downloads:,} weekly downloads")
    else:
        _row("metadata", "na", "N/A — no download data for this ecosystem")

    if signals.socket.socket_score is not None:
        s = signals.socket.socket_score
        _row("socket", "ok" if s >= 70 else ("warn" if s >= 40 else "bad"), f"score {s}/100")
    else:
        _row("socket", "na", "N/A — no data")

    if signals.osv.osv_vulnerabilities:
        _row("osv", "bad", f"{len(signals.osv.osv_vulnerabilities)} known vulnerabilities")
    else:
        _row("osv", "ok", "no known vulnerabilities")

    if signals.diff.install_script_added:
        _row("diff", "bad", "install script added")
    else:
        _row("diff", "ok", "no suspicious patterns")

    if signals.maintainer.maintainer_changed:
        _row("maintainer", "warn", "maintainer changed")
    else:
        _row("maintainer", "ok", "no changes detected")

    h = signals.age.release_age_hours
    if h is not None:
        _row("age", "warn" if h < 168 else "ok", f"released {_format_age(h)} ago")
    else:
        _row("age", "na", "release age unknown")

    if signals.attestation.has_attestation:
        _row("attestation", "ok", "build provenance verified")
    else:
        _row("attestation", "na", "N/A — no build provenance")

    if signals.release.github_release_exists:
        _row("release_notes", "ok", "GitHub release found")
    else:
        _row("release_notes", "na", "N/A — no GitHub release")

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
        _row("scorecard", "ok" if sc >= 7 else ("warn" if sc >= 4 else "bad"), f"score {sc:.1f}/10")
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

# Flags beyond this count are folded into a <details> block for YELLOW verdicts,
# so routine bumps with many minor signals don't drown out the important ones.
_FLAG_FOLD_THRESHOLD = 3


def format_comment(pr: PRContext, verdict: Verdict, signals: PackageChecks | None = None) -> str:
    badge = _BADGE.get(verdict.classification, verdict.classification.upper())

    lines = [
        f"## Dependency Scout — {badge}",
        "",
        f"**Confidence:** {verdict.confidence:.0%}",
        "",
        f"> {_sanitize_reasoning(verdict.reasoning)}",
        "",
    ]

    if verdict.flags:
        sanitized = [_sanitize_reasoning(f) for f in verdict.flags]
        # RED flags are always fully visible. YELLOW with many flags collapses the tail
        # so the comment doesn't drown the reviewer in low-priority noise.
        if verdict.classification == "red" or len(sanitized) <= _FLAG_FOLD_THRESHOLD:
            lines += ["**Flags:**", *[f"- {f}" for f in sanitized], ""]
        else:
            visible = sanitized[:_FLAG_FOLD_THRESHOLD]
            hidden = sanitized[_FLAG_FOLD_THRESHOLD:]
            noun = "check" if len(hidden) == 1 else "checks"
            lines += ["**Flags:**", *[f"- {f}" for f in visible]]
            lines += [
                f"<details><summary>and {len(hidden)} more {noun}</summary>",
                "",
                *[f"- {f}" for f in hidden],
                "",
                "</details>",
                "",
            ]

    if signals:
        lines += _signals_table(signals) + [""]

    lines += [
        "---",
        "_[Dependency Scout](https://github.com/temporal-community/dependency-scout) — "
        "automated supply-chain vetting for Dependabot/Renovate PRs_",
    ]

    return "\n".join(lines)
