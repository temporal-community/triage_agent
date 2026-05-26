from typing import Literal
from pydantic import BaseModel, field_validator


def _validate_ecosystem_name(v: str) -> str:
    try:
        from ecosystems import get_provider
    except Exception:
        # The Temporal workflow sandbox blocks httpx (imported by ecosystems).
        # Skip validation — the ecosystem name was already validated at the webhook boundary.
        return v
    try:
        get_provider(v)
    except ValueError:
        raise ValueError(f"Unknown ecosystem: {v!r} — no provider registered for this name")
    return v


class PRContext(BaseModel):
    repo: str  # "owner/name"
    pr_number: int
    pr_author: str  # "dependabot[bot]" or "renovate[bot]"
    installation_id: int | None = None  # GitHub App installation ID; None for token-auth platforms
    platform: Literal["github", "gitlab"] = "github"
    ecosystem: str
    package_name: str
    old_version: str
    new_version: str
    head_sha: str = ""  # PR branch HEAD SHA at webhook receipt time
    dry_run: bool = False  # when True, skip posting comments/actions (triage --dry-run)

    @field_validator("ecosystem")
    @classmethod
    def ecosystem_must_be_registered(cls, v: str) -> str:
        return _validate_ecosystem_name(v)


class PRFilesChecks(BaseModel):
    unexpected_files: list[str] = []  # CI/infra/script paths that shouldn't appear in a dep-bump PR


class ActionsUsageChecks(BaseModel):
    flags: list[str] = []  # one entry per workflow file that uses the bumped action


class RepoConfig(BaseModel):
    """Loaded from .github/dependency-scout.yml in target repo. All fields optional.

    Default behavior (no config file): posts a comment on every PR, closes RED PRs,
    no auto-merge, no review requests. Set block_classifications: [] for fully observe-only.
    """

    auto_merge_enabled: bool = False
    reviewers: list[str] = []
    min_release_age_hours: int = 168  # 7 days
    auto_merge_classifications: list[str] = ["green"]
    auto_merge_min_confidence: float = 0.90  # classifier must reach this confidence to auto-merge
    block_classifications: list[str] = [
        "red"
    ]  # close PRs classified as RED by default; set [] to observe-only
    max_new_dependencies: int = 5  # flag as yellow when more direct deps than this are added
    extra_check_activities: list[
        str
    ] = []  # additional Temporal activity names to call; each receives (ecosystem, package, old_version, new_version) and must return a JSON-serializable dict
