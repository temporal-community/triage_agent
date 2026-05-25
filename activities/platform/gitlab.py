"""GitLab PlatformClient implementation."""

from __future__ import annotations

import os
from urllib.parse import quote

from temporalio import activity
from temporalio.exceptions import ApplicationError

from activities.models import PRContext, PRFilesSignals, Verdict
from helpers.comment_formatter import format_comment
from helpers.http import get_client

# CI/infra paths that should never appear in a dep-bump MR
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
    ".gitlab/",
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


class GitLabPlatformClient:
    """PlatformClient for GitLab (cloud or self-hosted)."""

    def __init__(self, base_url: str = "https://gitlab.com") -> None:
        self._base_url = base_url.rstrip("/")

    def _dry_run(self) -> bool:
        return not os.environ.get("GITLAB_TOKEN")

    def _headers(self) -> dict:
        token = os.environ.get("GITLAB_TOKEN", "")
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    def _project_url(self, pr: PRContext) -> str:
        encoded = quote(pr.repo, safe="")
        return f"{self._base_url}/api/v4/projects/{encoded}"

    async def comment(self, pr: PRContext, verdict: Verdict) -> None:
        body = format_comment(pr, verdict)
        if self._dry_run():
            activity.logger.info(f"[dry-run] Would post on {pr.repo}!{pr.pr_number}:\n{body}")
            return
        client = get_client()
        resp = await client.post(
            f"{self._project_url(pr)}/merge_requests/{pr.pr_number}/notes",
            headers=self._headers(),
            json={"body": body},
            timeout=15.0,
        )
        if resp.status_code == 401:
            raise ApplicationError("GitLab auth failed", non_retryable=True)
        resp.raise_for_status()
        activity.logger.info(f"Posted comment on {pr.repo}!{pr.pr_number}")

    async def merge_pr(self, pr: PRContext) -> None:
        if self._dry_run():
            activity.logger.info(f"[dry-run] Would merge {pr.repo}!{pr.pr_number}")
            return
        client = get_client()
        mr_resp = await client.get(
            f"{self._project_url(pr)}/merge_requests/{pr.pr_number}",
            headers=self._headers(),
            timeout=15.0,
        )
        mr_resp.raise_for_status()
        mr_data = mr_resp.json()

        if mr_data.get("state") != "opened":
            raise ApplicationError(
                f"MR !{pr.pr_number} is {mr_data.get('state')}, cannot merge",
                non_retryable=True,
            )
        if pr.head_sha and mr_data.get("sha") != pr.head_sha:
            raise ApplicationError(
                f"MR !{pr.pr_number} HEAD SHA changed since triage began "
                f"(expected {pr.head_sha}, got {mr_data.get('sha')}) — re-triage required",
                non_retryable=True,
            )

        merge_resp = await client.put(
            f"{self._project_url(pr)}/merge_requests/{pr.pr_number}/merge",
            headers=self._headers(),
            json={"squash": True, "sha": mr_data.get("sha")},
            timeout=15.0,
        )
        if merge_resp.status_code == 405:
            raise ApplicationError(
                f"MR !{pr.pr_number} not mergeable — pipeline may still be running",
                non_retryable=False,
            )
        if merge_resp.status_code == 422:
            raise ApplicationError(
                f"MR !{pr.pr_number} merge failed: {merge_resp.json().get('message')}",
                non_retryable=True,
            )
        merge_resp.raise_for_status()
        activity.logger.info(f"Merged {pr.repo}!{pr.pr_number} (squash)")

    async def close_pr(self, pr: PRContext, reason: str, ignore_bot: bool = False) -> None:
        body = f"**Triage Agent — closing this MR.**\n\n{reason}"
        if self._dry_run():
            activity.logger.info(f"[dry-run] Would close {pr.repo}!{pr.pr_number}: {reason}")
            return
        client = get_client()
        comment_resp = await client.post(
            f"{self._project_url(pr)}/merge_requests/{pr.pr_number}/notes",
            headers=self._headers(),
            json={"body": body},
            timeout=15.0,
        )
        comment_resp.raise_for_status()
        close_resp = await client.put(
            f"{self._project_url(pr)}/merge_requests/{pr.pr_number}",
            headers=self._headers(),
            json={"state_event": "close"},
            timeout=15.0,
        )
        if close_resp.status_code == 422:
            raise ApplicationError(
                f"MR !{pr.pr_number} could not be closed: {close_resp.json().get('message')}",
                non_retryable=True,
            )
        close_resp.raise_for_status()
        activity.logger.info(f"Closed {pr.repo}!{pr.pr_number}: {reason}")

    async def request_review(self, pr: PRContext, reviewers: list[str]) -> None:
        if self._dry_run():
            activity.logger.info(
                f"[dry-run] Would request review on {pr.repo}!{pr.pr_number} from {reviewers}"
            )
            return
        # GitLab requires user IDs for reviewer assignment; resolve usernames first
        client = get_client()
        reviewer_ids: list[int] = []
        for username in reviewers:
            resp = await client.get(
                f"{self._base_url}/api/v4/users",
                headers=self._headers(),
                params={"username": username},
                timeout=15.0,
            )
            if resp.status_code == 200 and resp.json():
                reviewer_ids.append(resp.json()[0]["id"])
        if reviewer_ids:
            resp = await client.put(
                f"{self._project_url(pr)}/merge_requests/{pr.pr_number}",
                headers=self._headers(),
                json={"reviewer_ids": reviewer_ids},
                timeout=15.0,
            )
            resp.raise_for_status()
        activity.logger.info(f"Requested review on {pr.repo}!{pr.pr_number} from {reviewers}")

    async def label(self, pr: PRContext, label_name: str) -> None:
        if self._dry_run():
            activity.logger.info(
                f"[dry-run] Would add label '{label_name}' to {pr.repo}!{pr.pr_number}"
            )
            return
        client = get_client()
        resp = await client.put(
            f"{self._project_url(pr)}/merge_requests/{pr.pr_number}",
            headers=self._headers(),
            json={"add_labels": label_name},
            timeout=15.0,
        )
        resp.raise_for_status()
        activity.logger.info(f"Added label '{label_name}' to {pr.repo}!{pr.pr_number}")

    async def check_pr_files(self, pr: PRContext) -> PRFilesSignals:
        if self._dry_run():
            return PRFilesSignals()
        client = get_client()
        resp = await client.get(
            f"{self._project_url(pr)}/merge_requests/{pr.pr_number}/changes",
            headers=self._headers(),
            params={"per_page": 100},
            timeout=15.0,
        )
        if resp.status_code == 401:
            raise ApplicationError("GitLab auth failed", non_retryable=True)
        resp.raise_for_status()
        changes = resp.json().get("changes", [])
        unexpected = [c["new_path"] for c in changes if _is_ci_infra_file(c["new_path"])]
        return PRFilesSignals(unexpected_files=unexpected)
