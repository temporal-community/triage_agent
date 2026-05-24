from typing import Literal
from pydantic import BaseModel, Field


class PRContext(BaseModel):
    repo: str                           # "owner/name"
    pr_number: int
    pr_author: str                      # "dependabot[bot]" or "renovate[bot]"
    installation_id: int                # GitHub App installation
    ecosystem: Literal["pip", "npm", "rubygems", "maven", "composer", "nuget", "cargo", "go"]
    package_name: str
    old_version: str
    new_version: str
    head_sha: str = ""                  # PR branch HEAD SHA at webhook receipt time


class RepoConfig(BaseModel):
    """Loaded from .github/triage-agent.yml in target repo. All fields optional.

    Default behavior (no config file): posts a comment on every PR, closes RED PRs,
    no auto-merge, no review requests. Set block_classifications: [] for fully observe-only.
    """
    auto_merge_enabled: bool = False
    reviewers: list[str] = []
    min_release_age_hours: int = 168        # 7 days
    auto_merge_classifications: list[str] = ["green"]
    auto_merge_min_confidence: float = 0.80  # classifier must reach this confidence to auto-merge
    block_classifications: list[str] = ["red"]  # close PRs classified as RED by default; set [] to observe-only
    max_new_dependencies: int = 5           # flag as yellow when more direct deps than this are added


# Partial signal models — one per signal activity, nested into PackageSignals in the workflow.

class PyPISignals(BaseModel):
    weekly_downloads: int | None = None
    is_major_bump: bool = False
    package_description: str | None = None


class SocketSignals(BaseModel):
    socket_score: int | None = None
    socket_alerts: list[str] = []


class OSVSignals(BaseModel):
    osv_vulnerabilities: list[str] = []


class DiffSignals(BaseModel):
    diff_summary: str = ""
    diff_size_bytes: int = 0
    install_script_added: bool = False
    install_script_changed: bool = False
    new_dependency_count: int = 0  # net new direct dependencies added across manifest files
    network_calls_in_lib: bool = False   # new outbound HTTP calls added to non-install-hook library code
    binary_data_added: bool = False      # new file with binary/non-text content in a non-binary-extension file


class PRFilesSignals(BaseModel):
    unexpected_files: list[str] = []  # CI/infra/script paths that shouldn't appear in a dep-bump PR


class VersionLineSignals(BaseModel):
    stale_version_line: bool = False  # bump targets an older major while a newer stable major is active
    latest_major: int | None = None   # highest stable major in the registry
    bump_major: int | None = None     # major of the version being bumped to


class MaintainerSignals(BaseModel):
    maintainer_changed: bool = False


class ReleaseAgeSignals(BaseModel):
    release_age_hours: float | None = None   # None when upload_time is missing from PyPI metadata


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
    ecosystem: Literal["pip", "npm", "rubygems", "maven", "composer", "nuget", "cargo", "go"]
    package_name: str
    old_version: str
    new_version: str
    pypi: PyPISignals = Field(default_factory=PyPISignals)
    socket: SocketSignals = Field(default_factory=SocketSignals)
    osv: OSVSignals = Field(default_factory=OSVSignals)
    diff: DiffSignals = Field(default_factory=DiffSignals)
    maintainer: MaintainerSignals = Field(default_factory=MaintainerSignals)
    age: ReleaseAgeSignals = Field(default_factory=ReleaseAgeSignals)
    attestation: AttestationSignals = Field(default_factory=AttestationSignals)
    release: ReleaseSignals = Field(default_factory=ReleaseSignals)
    version_line: VersionLineSignals = Field(default_factory=VersionLineSignals)
    deps_dev: DepsDevSignals = Field(default_factory=DepsDevSignals)
    scorecard: ScorecardSignals = Field(default_factory=ScorecardSignals)


class Verdict(BaseModel):
    classification: Literal["green", "yellow", "red"]
    confidence: float
    reasoning: str
    flags: list[str]
    release_age_hours: float | None = None      # passed through for per-repo age gate enforcement
    new_dependency_count: int = 0               # passed through for per-repo max_new_dependencies gate
