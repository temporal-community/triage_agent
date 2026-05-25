# Checks

**When do you need a new check?** When there's a new external data source you want to run on every bump — if you find yourself thinking "I wish the classifier knew about X."

Each check calls an external API or does a computation, then returns a structured result. The workflow runs all 11 in parallel and collects the results; checks do the actual work. For PR side-effect functions (comment, merge, close), see [`pr_actions/`](../pr_actions/README.md).

## Triage checks

These eleven checks run in parallel for every package bump. All degrade gracefully — if one fails or its API key is missing, the workflow continues with the remaining results.

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

`package_diff.compute` downloads and extracts the full package archive — it's the slowest check and runs on a longer timeout than the rest. It calls `activity.heartbeat()` at each phase (download → extract → artifact/source comparison) so Temporal can detect worker crashes mid-run rather than waiting for the full timeout to expire.

## Check naming convention

Each check function is registered under a string name (e.g. `"activities.metadata.fetch"`) that the workflow uses to schedule it. The name in `@activity.defn(name=...)` must match exactly what appears in `_CHECK_REGISTRY` in `workflows/package_triage_workflow.py`.

This codebase uses string names deliberately: `_CHECK_REGISTRY` is a data structure mapping field names to check names and result types, making it easy to add or reorder checks without touching workflow control flow. The trade-off is that name mismatches are caught at runtime rather than import time — see [CLAUDE.md](../CLAUDE.md) for the full convention.

## Worker auto-discovery

The worker (`worker.py`) automatically discovers and registers every check function found in `checks/*.py` and `pr_actions/*.py`. **You do not need to manually register new checks** — just put the file in this directory and restart the worker.

## Adding a new triage check

**Step 1 — create the check**

```python
# checks/mycheck.py
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

The fourth element is `True` if the check is slow (like `package_diff`) and needs a longer timeout.

**Step 4 — write tests and regenerate fixtures**

Add tests under `tests/`. The worker will auto-discover your new check file — no manual registration needed. Then regenerate the Temporal replay fixtures since the workflow history changed:

```bash
uv run python tests/generate_fixtures.py
```
