from typing import Literal
from pydantic import BaseModel


class PRContext(BaseModel):
    repo: str                           # "owner/name"
    pr_number: int
    pr_author: str                      # "dependabot[bot]" or "renovate[bot]"
    installation_id: int                # GitHub App installation
    ecosystem: Literal["pip", "npm", "rubygems"]
    package_name: str
    old_version: str
    new_version: str
    head_sha: str = ""                  # PR branch HEAD SHA at webhook receipt time


class RepoConfig(BaseModel):
    """Loaded from .github/triage-agent.yml in target repo. All fields optional."""
    auto_merge_enabled: bool = False
    reviewers: list[str] = []
    min_release_age_hours: int = 168        # 7 days
    auto_merge_classifications: list[str] = ["green"]
    block_classifications: list[str] = []   # e.g. ["red"] to close suspicious PRs


# Partial signal models — one per signal activity, merged into PackageSignals in the workflow.

class PyPISignals(BaseModel):
    weekly_downloads: int | None
    is_major_bump: bool
    package_description: str | None = None


class SocketSignals(BaseModel):
    socket_score: int | None
    socket_alerts: list[str]


class OSVSignals(BaseModel):
    osv_vulnerabilities: list[str]


class DiffSignals(BaseModel):
    diff_summary: str
    diff_size_bytes: int
    install_script_added: bool = False
    install_script_changed: bool = False


class MaintainerSignals(BaseModel):
    maintainer_changed: bool


class ReleaseAgeSignals(BaseModel):
    release_age_hours: float | None   # None when upload_time is missing from PyPI metadata


class AttestationSignals(BaseModel):
    has_attestation: bool = False           # new version has a verifiable SLSA/Sigstore attestation
    publisher_kind: str | None = None       # "GitHub", "GitLab", etc.
    publisher_repo: str | None = None       # e.g. "psf/requests"
    publisher_changed: bool = False         # old version had a different trusted publisher
    old_publisher_repo: str | None = None   # previous publisher repo (context when changed)
    publisher_account_age_days: int | None = None  # age of the publisher's GitHub account


class PackageSignals(BaseModel):
    ecosystem: Literal["pip", "npm", "rubygems"]
    package_name: str
    old_version: str
    new_version: str
    release_age_hours: float | None
    is_major_bump: bool
    socket_score: int | None
    socket_alerts: list[str]
    osv_vulnerabilities: list[str]
    diff_summary: str
    diff_size_bytes: int
    maintainer_changed: bool
    weekly_downloads: int | None
    package_description: str | None = None
    install_script_added: bool = False
    install_script_changed: bool = False
    has_attestation: bool = False
    publisher_kind: str | None = None
    publisher_repo: str | None = None
    publisher_changed: bool = False
    old_publisher_repo: str | None = None
    publisher_account_age_days: int | None = None


class Verdict(BaseModel):
    classification: Literal["green", "yellow", "red"]
    confidence: float
    reasoning: str
    flags: list[str]
    release_age_hours: float | None = None  # passed through for per-repo age gate enforcement
