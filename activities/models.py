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
    """Loaded from .github/triage-agent.yml in target repo. All fields optional.

    Default behavior (no config file): observe-only — posts a comment on every PR,
    no auto-merge, no review requests, no blocking.
    """
    auto_merge_enabled: bool = False
    reviewers: list[str] = []
    min_release_age_hours: int = 168        # 7 days
    auto_merge_classifications: list[str] = ["green"]
    block_classifications: list[str] = []   # e.g. ["red"] to close suspicious PRs
    max_new_dependencies: int = 5           # flag as yellow when more direct deps than this are added


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
    new_dependency_count: int = 0  # net new direct dependencies added across manifest files


class PRFilesSignals(BaseModel):
    unexpected_files: list[str] = []  # CI/infra/script paths that shouldn't appear in a dep-bump PR


class VersionLineSignals(BaseModel):
    stale_version_line: bool = False  # bump targets an older major while a newer stable major is active
    latest_major: int | None = None   # highest stable major in the registry
    bump_major: int | None = None     # major of the version being bumped to


class MaintainerSignals(BaseModel):
    maintainer_changed: bool


class ReleaseAgeSignals(BaseModel):
    release_age_hours: float | None   # None when upload_time is missing from PyPI metadata


class ReleaseSignals(BaseModel):
    github_release_exists: bool = False
    release_author: str | None = None            # GitHub login who created the release
    release_is_automated: bool = False           # True if github-actions[bot] or similar bot
    timestamp_skew_minutes: float | None = None  # abs(registry_publish - gh_release_created)
    possible_rerelease: bool = False             # published_at lags created_at by >24h
    release_body: str | None = None             # release notes, truncated to 3 000 chars
    tag_signature_verified: bool | None = None  # None = no annotated tag; True/False = GH verification result
    tag_was_previously_signed: bool = False     # old version had a verified signed tag; new one doesn't
    metadata_repo: str | None = None            # "owner/repo" extracted from package registry metadata (project_urls / repository / source_code_uri)


class DepsDevSignals(BaseModel):
    is_deprecated: bool = False
    deprecated_reason: str | None = None


class ScorecardSignals(BaseModel):
    scorecard_score: float | None = None
    scorecard_repo: str | None = None           # "owner/repo" that was queried
    scorecard_maintained: int | None = None     # 0-10 or None if N/A
    scorecard_dangerous_workflow: int | None = None
    scorecard_token_permissions: int | None = None
    scorecard_branch_protection: int | None = None
    scorecard_signed_releases: int | None = None


class AttestationSignals(BaseModel):
    has_attestation: bool = False           # new version has a verifiable SLSA/Sigstore attestation
    publisher_kind: str | None = None       # "GitHub", "GitLab", etc.
    publisher_repo: str | None = None       # e.g. "psf/requests"
    publisher_changed: bool = False         # old version had a different trusted publisher
    old_publisher_repo: str | None = None   # previous publisher repo (context when changed)
    publisher_account_age_days: int | None = None  # age of the publisher's GitHub account
    source_ref: str | None = None           # git ref the build ran against, e.g. "refs/tags/v1.2.3"
    source_commit_sha: str | None = None    # git commit SHA the artifact was built from
    build_invocation_id: str | None = None  # CI run URL / ID from SLSA provenance
    oidc_first_time: bool = False           # True when old version had no attestation but new one does (personal→CI migration)


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
    new_dependency_count: int = 0
    github_release_exists: bool = False
    release_author: str | None = None
    release_is_automated: bool = False
    timestamp_skew_minutes: float | None = None
    possible_rerelease: bool = False
    release_body: str | None = None
    tag_signature_verified: bool | None = None
    tag_was_previously_signed: bool = False
    has_attestation: bool = False
    publisher_kind: str | None = None
    publisher_repo: str | None = None
    publisher_changed: bool = False
    old_publisher_repo: str | None = None
    publisher_account_age_days: int | None = None
    source_ref: str | None = None
    source_commit_sha: str | None = None
    build_invocation_id: str | None = None
    oidc_first_time: bool = False
    metadata_repo: str | None = None            # from ReleaseSignals — registry-declared GitHub repo
    stale_version_line: bool = False
    latest_major: int | None = None
    bump_major: int | None = None
    is_deprecated: bool = False
    deprecated_reason: str | None = None
    scorecard_score: float | None = None
    scorecard_repo: str | None = None
    scorecard_maintained: int | None = None
    scorecard_dangerous_workflow: int | None = None
    scorecard_token_permissions: int | None = None
    scorecard_branch_protection: int | None = None
    scorecard_signed_releases: int | None = None


class Verdict(BaseModel):
    classification: Literal["green", "yellow", "red"]
    confidence: float
    reasoning: str
    flags: list[str]
    release_age_hours: float | None = None      # passed through for per-repo age gate enforcement
    new_dependency_count: int = 0               # passed through for per-repo max_new_dependencies gate
