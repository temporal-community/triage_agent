# Activities

Activities are the individual units of work that Temporal executes, retries, and tracks. Each one calls an external API or does a computation, then returns a structured result. The workflow orchestrates them; activities do the actual work.

There are two groups: **triage checks** (run by `PackageTriageWorkflow` to assess a package) and **PR actions** (run by `PRActionWorkflow` to act on the verdict).

## Triage checks

These eleven activities run in parallel for every package bump. All degrade gracefully — if one fails or its API key is missing, the workflow continues with the remaining results.

| File | Activity name | Returns | External service | API key |
|---|---|---|---|---|
| `metadata.py` | `activities.metadata.fetch` | `MetadataChecks` | Package registry (via ecosystem provider) | None |
| `osv.py` | `activities.osv.check` | `OSVChecks` | [OSV.dev](https://osv.dev) vulnerability database | None |
| `socket.py` | `activities.socket.score` | `SocketChecks` | [Socket.dev](https://socket.dev) supply chain scoring | `SOCKET_API_KEY` |
| `package_diff.py` | `activities.package_diff.compute` | `PackageDiffChecks` | Package registry (archive download) | `GITHUB_TOKEN` (optional, for artifact-vs-source comparison) |
| `maintainer.py` | `activities.maintainer.history` | `MaintainerChecks` | Package registry (via ecosystem provider) | None |
| `release_age.py` | `activities.release_age.check` | `ReleaseAgeChecks` | Package registry (via ecosystem provider) | None |
| `attestation.py` | `activities.attestation.check` | `AttestationChecks` | Package registry provenance endpoint | None |
| `release_notes.py` | `activities.release_notes.check` | `ReleaseChecks` | GitHub / GitLab API | `GITHUB_TOKEN` / `GITLAB_TOKEN` (optional) |
| `version_lineage.py` | `activities.version_lineage.check` | `VersionLineageChecks` | Package registry | None |
| `depsdev.py` | `activities.depsdev.fetch` | `DepsDevChecks` | [deps.dev](https://deps.dev) | None |
| `scorecard.py` | `activities.scorecard.fetch` | `ScorecardChecks` | [OpenSSF Scorecard](https://securityscorecards.dev) | None |

`package_diff.compute` downloads and extracts the full package archive — it's the slowest activity and runs on a longer timeout than the rest.

## PR action activities

These live in `platform_activities.py` and are called by `PRActionWorkflow` after a verdict is reached. They talk to the GitHub or GitLab API to act on the PR.

| Activity name | What it does |
|---|---|
| `activities.platform.comment` | Posts the verdict comment on the PR |
| `activities.platform.merge_pr` | Auto-merges the PR |
| `activities.platform.close_pr` | Closes the PR with a reason |
| `activities.platform.label` | Adds a label to the PR |
| `activities.platform.request_review` | Requests review from configured reviewers |
| `activities.platform.check_pr_files` | Checks whether the PR touches unexpected files (CI scripts, Dockerfiles) |
| `activities.platform.fetch_repo_config` | Fetches `.github/dependency-scout.yml` from the target repo |

## Activity naming convention

Activity names are strings, not imports. The string registered with `@activity.defn(name=...)` must match exactly what the workflow passes to `workflow.execute_activity(...)`. This is a Temporal requirement for determinism — see [CLAUDE.md](../CLAUDE.md) for details.

## Adding a new triage check

**Step 1 — create the activity**

```python
# activities/mycheck.py
from temporalio import activity
from models import MyChecks

@activity.defn(name="activities.mycheck.fetch")
async def fetch(ecosystem: str, package: str, old_version: str, new_version: str) -> MyChecks:
    ...
    return MyChecks(...)
```

**Step 2 — add a model**

Add `MyChecks` to `models/__init__.py` as a `BaseModel` subclass, and add it as a field on `PackageChecks`.

**Step 3 — register in the workflow**

Add a row to `_CHECK_REGISTRY` in `workflows/package_triage_workflow.py`:

```python
("mycheck", "activities.mycheck.fetch", MyChecks, False),
```

The fourth element is `True` if the activity is slow (like `package_diff`) and needs a longer timeout.

**Step 4 — register with the worker**

Import and include `fetch` in the worker's activity list so Temporal knows to route tasks to it.

**Step 5 — write tests and regenerate fixtures**

Add tests under `tests/`. Then regenerate the Temporal replay fixtures since the workflow history changed:

```bash
uv run python tests/generate_fixtures.py
```
