"""GitHub PlatformClient implementation."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import httpx

from temporalio import activity
from temporalio.exceptions import ApplicationError

from models import PRContext, PackageChecks, PRFilesChecks, ActionsUsageChecks, Verdict
from helpers.comment_formatter import format_comment
from helpers.http import get_client

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
# AI assistant and IDE config files that can execute code on open/load.
# A dep-bump PR has no legitimate reason to touch these.
_AI_IDE_HOOK_EXACT: frozenset[str] = frozenset(
    {
        ".claude/settings.json",  # Claude Code SessionStart hooks
        ".claude/settings.local.json",
        ".cursor/rules",  # Cursor AI rules (also checked in diff for zero-width chars)
        ".cursorrules",
        ".vscode/tasks.json",  # VSCode folderOpen / onStartupFinished task triggers
        ".vscode/launch.json",
        ".vscode/extensions.json",
        ".idea/workspace.xml",  # JetBrains auto-run configs
        ".idea/runConfigurations",
        ".devcontainer/devcontainer.json",
        ".devcontainer.json",
    }
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
    if path in _AI_IDE_HOOK_EXACT:
        return True
    if any(path.startswith(p) for p in _CI_INFRA_PATH_PREFIXES):
        return True
    name_lower = name.lower()
    if name_lower.startswith("dockerfile") or name_lower.startswith("docker-compose"):
        return True
    return any(name_lower.endswith(s) for s in _CI_INFRA_SCRIPT_SUFFIXES)


def _extract_action_usages(content: str, action_name: str, filename: str) -> list[str]:
    """Parse workflow YAML and return one usage description per step that references action_name."""
    import yaml  # noqa: PLC0415

    try:
        data = yaml.safe_load(content)
    except Exception:
        return []
    if not isinstance(data, dict):
        return []
    results: list[str] = []
    for job in (data.get("jobs") or {}).values():
        if not isinstance(job, dict):
            continue
        for step in job.get("steps") or []:
            if not isinstance(step, dict):
                continue
            uses: str = step.get("uses") or ""
            action_part = uses.split("@")[0] if "@" in uses else uses
            if action_part.lower() != action_name.lower():
                continue
            with_inputs: dict = step.get("with") or {}
            if with_inputs:
                inputs_str = ", ".join(f"{k}: {v}" for k, v in with_inputs.items())
                results.append(f"workflow {filename} uses {uses} — inputs: {inputs_str}")
            else:
                results.append(f"workflow {filename} uses {uses} (no inputs configured)")
    return results


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

    async def comment(
        self, pr: PRContext, verdict: Verdict, signals: PackageChecks | None = None
    ) -> str | None:
        body = format_comment(pr, verdict, signals)
        if self._dry_run():
            activity.logger.info(f"[dry-run] Would post on {pr.repo}#{pr.pr_number}:\n{body}")
            return None
        headers = await self._get_headers()
        client = get_client()
        # Dedup: find all prior Scout comments, delete extras, update the survivor.
        keep_url, stale_ids = await self._find_scout_comments(client, pr, headers)
        for stale_id in stale_ids:
            try:
                await client.delete(
                    f"{self._repo_url(pr)}/issues/comments/{stale_id}",
                    headers=headers,
                    timeout=15.0,
                )
            except Exception:
                pass
        if keep_url:
            activity.logger.info(
                f"Updating existing comment on {pr.repo}#{pr.pr_number}: {keep_url}"
                + (f" (deleted {len(stale_ids)} duplicate(s))" if stale_ids else "")
            )
            keep_id = keep_url.split("#issuecomment-")[-1]
            resp = await client.patch(
                f"{self._repo_url(pr)}/issues/comments/{keep_id}",
                headers=headers,
                json={"body": body},
                timeout=15.0,
            )
            if resp.status_code == 401:
                raise ApplicationError("GitHub auth failed", non_retryable=True)
            resp.raise_for_status()
            return keep_url
        resp = await client.post(
            f"{self._repo_url(pr)}/issues/{pr.pr_number}/comments",
            headers=headers,
            json={"body": body},
            timeout=15.0,
        )
        if resp.status_code == 401:
            raise ApplicationError("GitHub auth failed", non_retryable=True)
        resp.raise_for_status()
        comment_url: str | None = resp.json().get("html_url")
        activity.logger.info(f"Posted comment on {pr.repo}#{pr.pr_number}: {comment_url}")
        return comment_url

    async def _find_scout_comments(
        self, client: "httpx.AsyncClient", pr: PRContext, headers: dict
    ) -> tuple[str | None, list[int]]:
        """Return (keep_url, stale_ids) for existing Dependency Scout comments.

        keep_url is the html_url of the oldest Scout comment (the one to update).
        stale_ids is the list of comment IDs for all subsequent duplicates to delete.
        """
        resp = await client.get(
            f"{self._repo_url(pr)}/issues/{pr.pr_number}/comments",
            headers=headers,
            params={"per_page": 100},
            timeout=15.0,
        )
        if resp.status_code != 200:
            return None, []
        scout = [c for c in resp.json() if "dependency-scout" in c.get("body", "")]
        if not scout:
            return None, []
        keep = scout[0]
        stale_ids = [c["id"] for c in scout[1:]]
        return keep.get("html_url"), stale_ids

    async def merge_pr(self, pr: PRContext) -> None:
        if self._dry_run():
            activity.logger.info(f"[dry-run] Would squash-merge {pr.repo}#{pr.pr_number}")
            return
        headers = await self._get_headers()
        client = get_client()
        pr_resp = await client.get(
            f"{self._repo_url(pr)}/pulls/{pr.pr_number}", headers=headers, timeout=15.0
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

        mergeable_state = pr_data.get("mergeable_state", "unknown")
        base_ref = pr_data.get("base", {}).get("ref", "the base branch")

        if mergeable_state == "behind":
            raise ApplicationError(
                f"PR #{pr.pr_number} branch is behind {base_ref!r} — will close so Dependabot can recreate with an updated branch",
                type="stale_branch",
                non_retryable=True,
            )
        if mergeable_state == "dirty":
            raise ApplicationError(
                f"PR #{pr.pr_number} has merge conflicts with {base_ref!r} — needs manual resolution",
                non_retryable=True,
            )

        merge_resp = await client.put(
            f"{self._repo_url(pr)}/pulls/{pr.pr_number}/merge",
            headers=headers,
            json={"merge_method": "squash", "sha": pr_data["head"]["sha"]},
            timeout=15.0,
        )
        if merge_resp.status_code == 405:
            if mergeable_state == "blocked":
                reason = "required checks have not passed yet"
            elif mergeable_state == "unknown":
                reason = "mergeability is still being computed — will retry"
            else:
                reason = f"mergeable_state={mergeable_state!r}"
            raise ApplicationError(
                f"PR #{pr.pr_number} not mergeable — {reason}",
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
        body = f"**Dependency Scout — closing this PR.**\n\n{reason}"
        if ignore_bot:
            body += "\n\n@dependabot ignore this dependency"
        if self._dry_run():
            activity.logger.info(f"[dry-run] Would close {pr.repo}#{pr.pr_number}: {reason}")
            return
        client = get_client()
        comment_resp = await client.post(
            f"{self._repo_url(pr)}/issues/{pr.pr_number}/comments",
            headers=await self._get_headers(),
            json={"body": body},
            timeout=15.0,
        )
        comment_resp.raise_for_status()
        close_resp = await client.patch(
            f"{self._repo_url(pr)}/pulls/{pr.pr_number}",
            headers=await self._get_headers(),
            json={"state": "closed"},
            timeout=15.0,
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
        client = get_client()
        resp = await client.post(
            f"{self._repo_url(pr)}/pulls/{pr.pr_number}/requested_reviewers",
            headers=await self._get_headers(),
            json={"reviewers": reviewers},
            timeout=15.0,
        )
        resp.raise_for_status()
        activity.logger.info(f"Requested review on {pr.repo}#{pr.pr_number} from {reviewers}")

    async def label(self, pr: PRContext, label_name: str) -> None:
        if self._dry_run():
            activity.logger.info(
                f"[dry-run] Would add label '{label_name}' to {pr.repo}#{pr.pr_number}"
            )
            return
        client = get_client()
        resp = await client.post(
            f"{self._repo_url(pr)}/issues/{pr.pr_number}/labels",
            headers=await self._get_headers(),
            json={"labels": [label_name]},
            timeout=15.0,
        )
        resp.raise_for_status()
        activity.logger.info(f"Added label '{label_name}' to {pr.repo}#{pr.pr_number}")

    async def fetch_actions_usage(self, pr: PRContext) -> ActionsUsageChecks:
        """Fetch .github/workflows/ from the target repo and extract usage of the bumped action.

        Returns empty results for non-github_actions ecosystems, dry-run mode, or API errors.
        """
        if pr.ecosystem != "github_actions" or self._dry_run():
            return ActionsUsageChecks()
        headers = await self._get_headers()
        client = get_client()
        resp = await client.get(
            f"{self._repo_url(pr)}/contents/.github/workflows",
            headers=headers,
            timeout=10.0,
        )
        if resp.status_code != 200:
            return ActionsUsageChecks()
        workflow_files = [
            f
            for f in resp.json()
            if isinstance(f, dict) and f.get("name", "").endswith((".yml", ".yaml"))
        ]
        import base64

        flags: list[str] = []
        for file_info in workflow_files[:20]:
            if len(flags) >= 10:
                break
            file_resp = await client.get(
                f"{self._repo_url(pr)}/contents/.github/workflows/{file_info['name']}",
                headers=headers,
                timeout=10.0,
            )
            if file_resp.status_code != 200:
                continue
            data = file_resp.json()
            if data.get("encoding") != "base64" or not data.get("content"):
                continue
            try:
                content = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
                flags.extend(_extract_action_usages(content, pr.package_name, file_info["name"]))
            except Exception:
                continue
        return ActionsUsageChecks(flags=flags)

    async def check_pr_files(self, pr: PRContext) -> PRFilesChecks:
        if self._dry_run():
            return PRFilesChecks()
        client = get_client()
        resp = await client.get(
            f"{self._repo_url(pr)}/pulls/{pr.pr_number}/files",
            headers=await self._get_headers(),
            params={"per_page": 100},
            timeout=15.0,
        )
        if resp.status_code == 401:
            raise ApplicationError("GitHub auth failed", non_retryable=True)
        resp.raise_for_status()

        def _is_unexpected(path: str) -> bool:
            if not _is_ci_infra_file(path):
                return False
            # For github_actions bumps, workflow file changes ARE the dependency
            # being updated — Dependabot edits every workflow that uses the action.
            if pr.ecosystem == "github_actions" and path.startswith(".github/workflows/"):
                return False
            return True

        unexpected = [f["filename"] for f in resp.json() if _is_unexpected(f["filename"])]
        return PRFilesChecks(unexpected_files=unexpected)


def create_client(pr: PRContext) -> GitHubPlatformClient:
    """Entry-point factory: called by get_platform_client() with the full PRContext."""
    return GitHubPlatformClient(installation_id=pr.installation_id)
