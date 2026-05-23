"""Activity: fetch OpenSSF Scorecard data for the package's upstream repo."""
from urllib.parse import quote

import httpx
from temporalio import activity

from activities.models import ScorecardSignals

_ECOSYSTEM_MAP = {"pip": "pypi", "npm": "npm", "rubygems": "rubygems"}

_SCORECARD_CHECKS = {
    "Maintained": "scorecard_maintained",
    "Dangerous-Workflow": "scorecard_dangerous_workflow",
    "Token-Permissions": "scorecard_token_permissions",
    "Branch-Protection": "scorecard_branch_protection",
    "Signed-Releases": "scorecard_signed_releases",
}


def _find_github_repo(data: dict) -> str | None:
    """Extract 'owner/repo' from a deps.dev version response."""
    for entry in data.get("relatedProjects", []):
        project_id = entry.get("projectKey", {}).get("id", "")
        if project_id.startswith("github.com/"):
            return project_id[len("github.com/"):]

    for link in data.get("links", []):
        url = link.get("url", "")
        if "github.com/" in url:
            # Extract owner/repo from URL like https://github.com/owner/repo
            after = url.split("github.com/", 1)[1]
            parts = after.strip("/").split("/")
            if len(parts) >= 2:
                return f"{parts[0]}/{parts[1]}"

    return None


@activity.defn(name="activities.scorecard.fetch")
async def fetch(ecosystem: str, package: str, old_version: str, new_version: str) -> ScorecardSignals:
    system = _ECOSYSTEM_MAP.get(ecosystem)
    if system is None:
        return ScorecardSignals()

    encoded_package = quote(package, safe="")
    encoded_version = quote(new_version, safe="")
    depsdev_url = f"https://api.deps.dev/v3alpha/systems/{system}/packages/{encoded_package}/versions/{encoded_version}"

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            # Step A — resolve GitHub repo via deps.dev
            deps_resp = await client.get(depsdev_url)
            if deps_resp.status_code != 200:
                return ScorecardSignals()

            repo = _find_github_repo(deps_resp.json())
            if repo is None:
                return ScorecardSignals()

            # Step B — query OpenSSF Scorecard
            sc_resp = await client.get(
                f"https://api.securityscorecards.dev/projects/github.com/{repo}",
                headers={"Accept": "application/json"},
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

        return ScorecardSignals(
            scorecard_score=scorecard_score,
            scorecard_repo=repo,
            scorecard_maintained=check_scores["scorecard_maintained"],
            scorecard_dangerous_workflow=check_scores["scorecard_dangerous_workflow"],
            scorecard_token_permissions=check_scores["scorecard_token_permissions"],
            scorecard_branch_protection=check_scores["scorecard_branch_protection"],
            scorecard_signed_releases=check_scores["scorecard_signed_releases"],
        )
    except Exception as exc:
        activity.logger.warning(f"Scorecard fetch failed for {package}@{new_version}: {exc!r}")
        return ScorecardSignals()
