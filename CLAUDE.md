# CLAUDE.md

Guidance for Claude Code when working in this repo. See [docs/architecture.md](docs/architecture.md) for design details.

## What this is

**dependency-scout** — vets Dependabot/Renovate PRs by gathering supply chain risk checks in parallel, classifying GREEN/YELLOW/RED, and acting on the verdict. Key principle: graceful degradation — zero API keys works (rule-based, log-only); gets smarter as keys are added.

Ecosystems implemented: pip, npm, RubyGems, Maven, NuGet, Cargo, Go modules, Composer.

## Module map

| Package | Purpose |
|---|---|
| `ecosystems/` | `EcosystemProviderBase` + one file per ecosystem (pip, npm, …) |
| `platforms/` | `PlatformClient` protocol + GitHub and GitLab implementations |
| `classifiers/` | `Classifier` protocol + Claude / OpenAI / Ollama / rule-based implementations |
| `models/` | All dataclasses — split across `pr.py`, `checks.py`, `verdict.py`, `package.py` |
| `activities/` | Thin Temporal `@activity.defn` wrappers — call into the packages above |
| `workflows/` | `PackageTriageWorkflow` and `PRActionWorkflow` |
| `helpers/` | GitHub App auth, comment formatting, config providers, HTTP client |
| `api/` | FastAPI webhook receiver |
| `checks/signatures/` | YAML pattern store for `package_diff.py` — add attack signatures here, no Python needed |

`ecosystems/`, `platforms/`, and `classifiers/` are the stable public extension points. Plugin authors import from them directly without touching Temporal.

## Non-obvious conventions

**Temporal activity references use string names, not imports:**
```python
# In workflow code — always by string
await workflow.execute_activity("activities.metadata.fetch", ...)

# Activity definition — name must match exactly
@activity.defn(name="activities.metadata.fetch")
async def fetch(...):
```
This is required for determinism. Never import activity functions directly into workflow code.

**Workflow-unsafe imports** go inside `with workflow.unsafe.imports_passed_through():`.

**Non-retryable errors:** use `ApplicationError(..., non_retryable=True)` for permanent failures (404, auth errors). Retryable errors just raise normally.

**Config filename:** `.github/dependency-scout.yml` in user repos was intentionally NOT renamed when the project was renamed — that would be a breaking change for existing installs.

**Plugin / entry points:** `ecosystems/`, `platforms/`, `classifiers/`, and `checks/signatures/` are all pluggable via Python entry points. Discovery happens at runtime via `importlib.metadata.entry_points` — there is no manual registry. Patch `importlib.metadata.entry_points` (not the module's own reference) when testing this path. Signature plugins use two groups: `dependency_scout.signatures` (callable returning a `Path` to a YAML directory) and `dependency_scout.signature_providers` (callable returning a `SignatureContribution`).

**`models/` is split into multiple files:** `pr.py`, `checks.py`, `verdict.py`, `package.py`. The package `__init__.py` re-exports everything, so `from models import Verdict` still works — but if you're adding a new model, put it in the right file.

## Commands

```bash
uv run ruff format .      # format
uv run ruff check .       # lint
uv run mypy .             # type check
uv run pytest             # all tests
uv run pytest \
  --cov=activities --cov=ecosystems --cov=platforms --cov=classifiers \
  --cov=models --cov=workflows --cov=helpers --cov=api --cov=checks \
  --cov-report=term-missing          # coverage (target ≥95%)
uv run pytest tests/test_workflow_replay.py -v   # replay/determinism tests
```

Note: `--cov` requires separate flags per module — the comma-separated form (`--cov=a,b,c`) silently collects no data.

## Replay tests

`tests/test_workflow_replay.py` loads fixtures from `tests/fixtures/` and replays through Temporal's `Replayer`. A replay failure = non-deterministic change in workflow code. Regenerate fixtures after intentional workflow changes:
```bash
uv run python tests/generate_fixtures.py
```

## Testing patterns

- HTTP mocked via `respx`
- Activities tested with `ActivityEnvironment`
- Workflow sandbox lines (the `with workflow.unsafe.imports_passed_through():` block at the top of each workflow file) are unreachable from unit tests — covered by replay fixtures instead, not a coverage gap to fix
