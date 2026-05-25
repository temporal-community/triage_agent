import os
import re
from models import PRContext, PackageChecks, Verdict


def _config_url(pr: PRContext) -> str:
    if pr.platform == "gitlab":
        base = os.environ.get("GITLAB_BASE_URL", "https://gitlab.com").rstrip("/")
        return f"{base}/{pr.repo}/-/blob/HEAD/.gitlab/triage-agent.yml"
    return f"https://github.com/{pr.repo}/blob/HEAD/.github/triage-agent.yml"


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
    ui_base = os.environ.get("TEMPORAL_UI_BASE_URL", "http://localhost:8233")
    ns = os.environ.get("TEMPORAL_NAMESPACE", "default")
    wf_id = f"triage-{pr.ecosystem}-{pr.package_name}-{pr.new_version}"
    wf_url = f"{ui_base}/namespaces/{ns}/workflows/{wf_id}"
    config_url = _config_url(pr)

    lines = [
        f"## Dependabot Triage Agent — {badge}",
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
            noun = "signal" if len(hidden) == 1 else "signals"
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
        lines += [
            "| Signal | Value |",
            "|--------|-------|",
            f"| Release age | {signals.age.release_age_hours:.0f}h |"
            if signals.age.release_age_hours is not None
            else "| Release age | unknown |",
            f"| Weekly downloads | {signals.metadata.weekly_downloads:,} |"
            if signals.metadata.weekly_downloads
            else "| Weekly downloads | unknown |",
            f"| Socket score | {signals.socket.socket_score}/100 |"
            if signals.socket.socket_score is not None
            else "| Socket score | unavailable |",
            f"| CVEs | {len(signals.osv.osv_vulnerabilities)} |",
            f"| Maintainer changed | {'yes' if signals.maintainer.maintainer_changed else 'no'} |",
            f"| Major bump | {'yes' if signals.metadata.is_major_bump else 'no'} |",
            f"| Diff size | {signals.diff.diff_size_bytes:,} bytes |",
            "",
        ]

    lines += [
        f"[View workflow run]({wf_url}) · [Configure triage behavior]({config_url})",
    ]

    return "\n".join(lines)
