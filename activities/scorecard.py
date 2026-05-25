"""Activity: fetch OpenSSF Scorecard data for the package's upstream repo."""

from urllib.parse import quote

from temporalio import activity

from activities.models import ScorecardSignals
from helpers.cache import ActivityCache
from helpers.http import get_client

_cache: ActivityCache = ActivityCache(ttl_seconds=86400)  # repo health changes slowly; 24h TTL

_ECOSYSTEM_MAP = {
    "pip": "pypi",
    "npm": "npm",
    "rubygems": "rubygems",
    "maven": "maven",
    "nuget": "nuget",
}

_SCORECARD_CHECKS = {
    "Maintained": "scorecard_maintained",
    "Dangerous-Workflow": "scorecard_dangerous_workflow",
    "Token-Permissions": "scorecard_token_permissions",
    "Branch-Protection": "scorecard_branch_protection",
    "Signed-Releases": "scorecard_signed_releases",
}


def _find_vcs_repo(data: dict) -> tuple[str, str] | None:
    """Extract (platform, 'owner/repo') from a deps.dev version response, or None.

    Scorecard API only supports GitHub; non-GitHub repos return None for graceful degradation.
    """
    from activities.ecosystems import parse_vcs_repo

    for entry in data.get("relatedProjects", []):
        project_id = entry.get("projectKey", {}).get("id", "")
        if project_id.startswith("github.com/"):
            return ("github", project_id[len("github.com/") :])

    for link in data.get("links", []):
        url = link.get("url", "")
        parsed = parse_vcs_repo(url)
        if parsed:
            return parsed

    return None


@activity.defn(name="activities.scorecard.fetch")
async def fetch(
    ecosystem: str, package: str, old_version: str, new_version: str
) -> ScorecardSignals:
    key = (ecosystem, package)  # scorecard is per-repo, not per-version
    if (hit := _cache.get(key)) is not None:
        activity.logger.debug("scorecard cache hit: %s", package)
        return hit

    system = _ECOSYSTEM_MAP.get(ecosystem)
    if system is None:
        return ScorecardSignals()

    encoded_package = quote(package, safe="")
    encoded_version = quote(new_version, safe="")
    depsdev_url = f"https://api.deps.dev/v3alpha/systems/{system}/packages/{encoded_package}/versions/{encoded_version}"

    try:
        client = get_client()
        # Step A — resolve GitHub repo via deps.dev
        deps_resp = await client.get(depsdev_url, timeout=20.0)
        if deps_resp.status_code != 200:
            return ScorecardSignals()

        vcs = _find_vcs_repo(deps_resp.json())
        if vcs is None or vcs[0] != "github":
            return ScorecardSignals()
        repo = vcs[1]

        # Step B — query OpenSSF Scorecard (GitHub-only API)
        sc_resp = await client.get(
            f"https://api.securityscorecards.dev/projects/github.com/{repo}",
            headers={"Accept": "application/json"},
            timeout=20.0,
        )

        if sc_resp.status_code != 200:
            return ScorecardSignals(scorecard_repo=repo)

        sc_data = sc_resp.json()
        score = sc_data.get("score")
        scorecard_score = float(score) if score is not None else None

        check_scores: dict[str, int | None] = {v: None for v in _SCORECARD_CHECKS.values()}
        for check in sc_data.get("checks", []):
            field = _SCORECARD_CHECKS.get(check.get("name", ""))
            if field is not None:
                raw = check.get("score")
                # Score of -1 means "not applicable"
                check_scores[field] = None if raw == -1 else raw

        result = ScorecardSignals(
            scorecard_score=scorecard_score,
            scorecard_repo=repo,
            scorecard_maintained=check_scores["scorecard_maintained"],
            scorecard_dangerous_workflow=check_scores["scorecard_dangerous_workflow"],
            scorecard_token_permissions=check_scores["scorecard_token_permissions"],
            scorecard_branch_protection=check_scores["scorecard_branch_protection"],
            scorecard_signed_releases=check_scores["scorecard_signed_releases"],
        )
        _cache.set(key, result)
        return result
    except Exception as exc:
        activity.logger.warning(f"Scorecard fetch failed for {package}@{new_version}: {exc!r}")
        return ScorecardSignals()
