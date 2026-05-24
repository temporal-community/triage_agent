"""GitHub PlatformClient implementation."""

from __future__ import annotations

import os

import httpx
from temporalio import activity
from temporalio.exceptions import ApplicationError

from activities.models import PRContext, PRFilesSignals, Verdict
from helpers.comment_formatter import format_comment

# ---------------------------------------------------------------------------
# CI/infra file detection — paths that should never change in a dep-bump PR
# ---------------------------------------------------------------------------

_CI_INFRA_EXACT: frozenset[str] = frozenset(
    {
        ".gitlab-ci.yml",
        ".gitlab-ci.yaml",
        "Jenkinsfile",
        ".travis.yml",
        ".travis.yaml",
        "bitbucket-pipelines.yml",
        "bitbucket-pipelines.yaml",
        ".drone.yml",
        ".drone.yaml",
        "appveyor.yml",
        "appveyor.yaml",
        ".dockerignore",
        "Makefile",
        "makefile",
        "GNUmakefile",
    }
)
_CI_INFRA_PATH_PREFIXES: tuple[str, ...] = (
    ".github/",
    ".circleci/",
    ".buildkite/",
)
_CI_INFRA_SCRIPT_SUFFIXES: tuple[str, ...] = (
    ".sh",
    ".bash",
    ".zsh",
    ".fish",
    ".ps1",
    ".psm1",
    ".psd1",
    ".bat",
    ".cmd",
)


def _is_ci_infra_file(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    if name in _CI_INFRA_EXACT:
        return True
    if any(path.startswith(p) for p in _CI_INFRA_PATH_PREFIXES):
        return True
    name_lower = name.lower()
    if name_lower.startswith("dockerfile") or name_lower.startswith("docker-compose"):
        return True
    return any(name_lower.endswith(s) for s in _CI_INFRA_SCRIPT_SUFFIXES)


class GitHubPlatformClient:
    def __init__(self, installation_id: int | None = None) -> None:
        self._installation_id = installation_id

    def _dry_run(self) -> bool:
        return not os.environ.get("GITHUB_TOKEN") and not os.environ.get("GITHUB_APP_ID")

    async def _get_headers(self) -> dict:
        if token := os.environ.get("GITHUB_TOKEN"):
            pass
        elif self._installation_id is not None:
            from helpers.github_app import get_installation_token

            token = await get_installation_token(self._installation_id)
        else:
            token = ""
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _repo_url(self, pr: PRContext) -> str:
        return f"https://api.github.com/repos/{pr.repo}"

    async def comment(self, pr: PRContext, verdict: Verdict) -> None:
        body = format_comment(pr, verdict)
        if self._dry_run():
            activity.logger.info(f"[dry-run] Would post on {pr.repo}#{pr.pr_number}:\n{body}")
            return
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{self._repo_url(pr)}/issues/{pr.pr_number}/comments",
                headers=await self._get_headers(),
                json={"body": body},
            )
            if resp.status_code == 401:
                raise ApplicationError("GitHub auth failed", non_retryable=True)
            resp.raise_for_status()
        activity.logger.info(f"Posted comment on {pr.repo}#{pr.pr_number}")

    async def merge_pr(self, pr: PRContext) -> None:
        if self._dry_run():
            activity.logger.info(f"[dry-run] Would squash-merge {pr.repo}#{pr.pr_number}")
            return
        headers = await self._get_headers()
        async with httpx.AsyncClient(timeout=15.0) as client:
            pr_resp = await client.get(
                f"{self._repo_url(pr)}/pulls/{pr.pr_number}", headers=headers
            )
            pr_resp.raise_for_status()
            pr_data = pr_resp.json()

            if pr_data["state"] != "open":
                raise ApplicationError(
                    f"PR #{pr.pr_number} is {pr_data['state']}, cannot merge",
                    non_retryable=True,
                )
            if pr.head_sha and pr_data["head"]["sha"] != pr.head_sha:
                raise ApplicationError(
                    f"PR #{pr.pr_number} HEAD SHA changed since triage began "
                    f"(expected {pr.head_sha}, got {pr_data['head']['sha']}) — re-triage required",
                    non_retryable=True,
                )

            merge_resp = await client.put(
                f"{self._repo_url(pr)}/pulls/{pr.pr_number}/merge",
                headers=headers,
                json={"merge_method": "squash", "sha": pr_data["head"]["sha"]},
            )
            if merge_resp.status_code == 405:
                raise ApplicationError(
                    f"PR #{pr.pr_number} not mergeable — CI may still be running",
                    non_retryable=False,
                )
            if merge_resp.status_code == 422:
                raise ApplicationError(
                    f"PR #{pr.pr_number} merge failed: {merge_resp.json().get('message')}",
                    non_retryable=True,
                )
            merge_resp.raise_for_status()
        activity.logger.info(f"Merged {pr.repo}#{pr.pr_number} (squash)")

    async def close_pr(self, pr: PRContext, reason: str, ignore_bot: bool = False) -> None:
        body = f"**Dependabot Triage Agent — closing this PR.**\n\n{reason}"
        if ignore_bot:
            body += "\n\n@dependabot ignore this dependency"
        if self._dry_run():
            activity.logger.info(f"[dry-run] Would close {pr.repo}#{pr.pr_number}: {reason}")
            return
        async with httpx.AsyncClient(timeout=15.0) as client:
            comment_resp = await client.post(
                f"{self._repo_url(pr)}/issues/{pr.pr_number}/comments",
                headers=await self._get_headers(),
                json={"body": body},
            )
            comment_resp.raise_for_status()
            close_resp = await client.patch(
                f"{self._repo_url(pr)}/pulls/{pr.pr_number}",
                headers=await self._get_headers(),
                json={"state": "closed"},
            )
            if close_resp.status_code == 422:
                raise ApplicationError(
                    f"PR #{pr.pr_number} could not be closed: {close_resp.json().get('message')}",
                    non_retryable=True,
                )
            close_resp.raise_for_status()
        activity.logger.info(f"Closed {pr.repo}#{pr.pr_number}: {reason}")

    async def request_review(self, pr: PRContext, reviewers: list[str]) -> None:
        if self._dry_run():
            activity.logger.info(
                f"[dry-run] Would request review on {pr.repo}#{pr.pr_number} from {reviewers}"
            )
            return
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{self._repo_url(pr)}/pulls/{pr.pr_number}/requested_reviewers",
                headers=await self._get_headers(),
                json={"reviewers": reviewers},
            )
            resp.raise_for_status()
        activity.logger.info(f"Requested review on {pr.repo}#{pr.pr_number} from {reviewers}")

    async def label(self, pr: PRContext, label_name: str) -> None:
        if self._dry_run():
            activity.logger.info(
                f"[dry-run] Would add label '{label_name}' to {pr.repo}#{pr.pr_number}"
            )
            return
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{self._repo_url(pr)}/issues/{pr.pr_number}/labels",
                headers=await self._get_headers(),
                json={"labels": [label_name]},
            )
            resp.raise_for_status()
        activity.logger.info(f"Added label '{label_name}' to {pr.repo}#{pr.pr_number}")

    async def check_pr_files(self, pr: PRContext) -> PRFilesSignals:
        if self._dry_run():
            return PRFilesSignals()
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"{self._repo_url(pr)}/pulls/{pr.pr_number}/files",
                headers=await self._get_headers(),
                params={"per_page": 100},
            )
            if resp.status_code == 401:
                raise ApplicationError("GitHub auth failed", non_retryable=True)
            resp.raise_for_status()
        unexpected = [f["filename"] for f in resp.json() if _is_ci_infra_file(f["filename"])]
        return PRFilesSignals(unexpected_files=unexpected)
