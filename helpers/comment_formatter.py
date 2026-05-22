import os
from activities.models import PRContext, PackageSignals, Verdict

_BADGE = {
    "green": "🟢 GREEN",
    "yellow": "🟡 YELLOW",
    "red": "🔴 RED",
}


def format_comment(pr: PRContext, verdict: Verdict, signals: PackageSignals | None = None) -> str:
    badge = _BADGE.get(verdict.classification, verdict.classification.upper())
    ui_base = os.environ.get("TEMPORAL_UI_BASE_URL", "http://localhost:8233")
    ns = os.environ.get("TEMPORAL_NAMESPACE", "default")
    wf_id = f"triage-{pr.ecosystem}-{pr.package_name}-{pr.new_version}"
    wf_url = f"{ui_base}/namespaces/{ns}/workflows/{wf_id}"
    config_url = f"https://github.com/{pr.repo}/blob/HEAD/.github/triage-agent.yml"

    lines = [
        f"## Dependabot Triage Agent — {badge}",
        "",
        f"**Confidence:** {verdict.confidence:.0%}",
        "",
        f"> {verdict.reasoning}",
        "",
    ]

    if verdict.flags:
        lines += ["**Flags:**", *[f"- {f}" for f in verdict.flags], ""]

    if signals:
        lines += [
            "| Signal | Value |",
            "|--------|-------|",
            f"| Release age | {signals.release_age_hours:.0f}h |",
            f"| Weekly downloads | {signals.weekly_downloads:,} |" if signals.weekly_downloads else "| Weekly downloads | unknown |",
            f"| Socket score | {signals.socket_score}/100 |" if signals.socket_score is not None else "| Socket score | unavailable |",
            f"| CVEs | {len(signals.osv_vulnerabilities)} |",
            f"| Maintainer changed | {'yes' if signals.maintainer_changed else 'no'} |",
            f"| Major bump | {'yes' if signals.is_major_bump else 'no'} |",
            f"| Diff size | {signals.diff_size_bytes:,} bytes |",
            "",
        ]

    lines += [
        f"[View workflow run]({wf_url}) · [Configure triage behavior]({config_url})",
    ]

    return "\n".join(lines)
