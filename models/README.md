# Models

All data structures used across the codebase live here in `__init__.py`. They are [Pydantic](https://docs.pydantic.dev) models — plain Python classes with type-checked fields and automatic validation.

## The big picture

```
PRContext  ──►  PackageChecks  ──►  Verdict
   │               │
   │               └─ one field per check activity (MetadataChecks, OSVChecks, ...)
   │
   └─ RepoConfig  (loaded from .github/dependency-scout.yml)
```

A PR comes in as a `PRContext`. The workflow runs all the check activities and collects their results into a `PackageChecks`. The classifier turns `PackageChecks` into a `Verdict`. `RepoConfig` controls what happens next (auto-merge, comment, close, etc.).

## Models reference

### `PRContext`
Everything known about the pull request: repo, PR number, platform (GitHub/GitLab), ecosystem, package name, old and new versions. Created at the webhook boundary and passed to `PRActionWorkflow`.

### `RepoConfig`
Per-repo settings loaded from `.github/dependency-scout.yml`. Controls auto-merge thresholds, which verdicts trigger a close, minimum release age before auto-merging, and which reviewers to notify. All fields have safe defaults — no config file is required.

### `PackageChecks`
The central data structure: one instance per package triage run. Contains the package identity fields plus one nested check model per activity. Every field defaults to an empty/safe value so a failed or skipped activity doesn't break the classifier.

| Field | Type | Populated by |
|---|---|---|
| `metadata` | `MetadataChecks` | `activities.metadata.fetch` |
| `socket` | `SocketChecks` | `activities.socket.score` |
| `osv` | `OSVChecks` | `activities.osv.check` |
| `diff` | `PackageDiffChecks` | `activities.package_diff.compute` |
| `maintainer` | `MaintainerChecks` | `activities.maintainer.history` |
| `age` | `ReleaseAgeChecks` | `activities.release_age.check` |
| `attestation` | `AttestationChecks` | `activities.attestation.check` |
| `release` | `ReleaseChecks` | `activities.release_notes.check` |
| `version_lineage` | `VersionLineageChecks` | `activities.version_lineage.check` |
| `deps_dev` | `DepsDevChecks` | `activities.depsdev.fetch` |
| `scorecard` | `ScorecardChecks` | `activities.scorecard.fetch` |
| `custom_checks` | `dict[str, Any]` | Plugin activities (via `extra_check_activities` config) |

### `Verdict`
The classifier's output: a `classification` (`"green"` / `"yellow"` / `"red"`), a `confidence` score (0–1), a `reasoning` paragraph, and a list of specific `flags`. The `PRActionWorkflow` reads this to decide what to do with the PR.

### Check models

Each of the following holds the raw results from one activity. They are deliberately narrow — each only knows about its own signal.

| Model | Key fields |
|---|---|
| `MetadataChecks` | `weekly_downloads`, `is_major_bump`, `package_description` |
| `SocketChecks` | `socket_score` (0–100), `socket_alerts` |
| `OSVChecks` | `osv_vulnerabilities` (list of CVE/OSV IDs) |
| `PackageDiffChecks` | `install_script_added`, `obfuscated_code`, `network_calls_in_lib`, `artifact_source_mismatch`, and more |
| `MaintainerChecks` | `maintainer_changed`, `new_maintainer_account_age_days` |
| `ReleaseAgeChecks` | `release_age_hours` |
| `AttestationChecks` | `has_attestation`, `publisher_repo`, `publisher_changed`, `source_commit_sha` |
| `ReleaseChecks` | `github_release_exists`, `tag_signature_verified`, `timestamp_skew_minutes`, `ci_workflow_changed_days_ago` |
| `VersionLineageChecks` | `stale_version_line`, `bump_major`, `latest_major` |
| `DepsDevChecks` | `is_deprecated`, `deprecated_reason` |
| `ScorecardChecks` | `scorecard_score`, `scorecard_dangerous_workflow`, `scorecard_branch_protection` |
| `PRFilesChecks` | `unexpected_files` (paths that shouldn't appear in a dep-bump PR) |

## Adding a new check model

1. Add a new `class MyChecks(BaseModel)` to `__init__.py`
2. Add a field `my_check: MyChecks = Field(default_factory=MyChecks)` to `PackageChecks`
3. Create the corresponding activity in `activities/` — see [`activities/README.md`](../activities/README.md)
