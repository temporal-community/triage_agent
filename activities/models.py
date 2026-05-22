from typing import Literal
from pydantic import BaseModel


class PRContext(BaseModel):
    repo: str                           # "owner/name"
    pr_number: int
    pr_author: str                      # "dependabot[bot]" or "renovate[bot]"
    installation_id: int                # GitHub App installation
    ecosystem: Literal["pip", "npm"]    # npm is v2; pip-only for v1
    package_name: str
    old_version: str
    new_version: str


class RepoConfig(BaseModel):
    """Loaded from .github/triage-agent.yml in target repo. All fields optional."""
    auto_merge_enabled: bool = False
    reviewers: list[str] = []
    min_release_age_hours: int = 168        # 7 days
    allowed_ecosystems: list[str] = ["pip", "npm"]
    auto_merge_classifications: list[str] = ["green"]
    block_classifications: list[str] = []   # e.g. ["red"] to force-close suspicious PRs


# Partial signal models — one per signal activity, merged into PackageSignals in the workflow.

class PyPISignals(BaseModel):
    weekly_downloads: int | None
    publish_account_age_days: int | None
    is_major_bump: bool


class SocketSignals(BaseModel):
    socket_score: int | None
    socket_alerts: list[str]


class OSVSignals(BaseModel):
    osv_vulnerabilities: list[str]


class DiffSignals(BaseModel):
    diff_summary: str
    diff_size_bytes: int


class MaintainerSignals(BaseModel):
    maintainer_changed: bool


class ReleaseAgeSignals(BaseModel):
    release_age_hours: float


class PackageSignals(BaseModel):
    ecosystem: Literal["pip", "npm"]
    package_name: str
    old_version: str
    new_version: str
    release_age_hours: float
    is_major_bump: bool
    socket_score: int | None
    socket_alerts: list[str]
    osv_vulnerabilities: list[str]
    diff_summary: str
    diff_size_bytes: int
    maintainer_changed: bool
    weekly_downloads: int | None
    publish_account_age_days: int | None


class Verdict(BaseModel):
    classification: Literal["green", "yellow", "red"]
    confidence: float
    reasoning: str
    flags: list[str]
