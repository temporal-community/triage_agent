# CLAUDE.md

Guidance for Claude Code when working in this repo. See [ARCHITECTURE.md](ARCHITECTURE.md) for design details.

## What this is

**dependency-scout** — vets Dependabot/Renovate PRs by gathering supply chain risk signals in parallel, classifying GREEN/YELLOW/RED, and acting on the verdict. Key principle: graceful degradation — zero API keys works (rule-based, log-only); gets smarter as keys are added.

Ecosystems: pip (production), npm (implemented, deployment pending).

## Non-obvious conventions

**Temporal activity references use string names, not imports:**
```python
# In workflow code — always by string
await workflow.execute_activity("activities.pypi_metadata.fetch", ...)

# Activity definition — name must match exactly
@activity.defn(name="activities.pypi_metadata.fetch")
async def fetch(...):
```
This is required for determinism. Never import activity functions directly into workflow code.

**Workflow-unsafe imports** go inside `with workflow.unsafe.imports_passed_through():`.

**Non-retryable errors:** use `ApplicationError(..., non_retryable=True)` for permanent failures (404, auth errors). Retryable errors just raise normally.

**Config filename:** `.github/dependency-scout.yml` in user repos was intentionally NOT renamed when the project was renamed — that would be a breaking change for existing installs.

## Commands

```bash
uv run ruff format .                    # format
uv run ruff check .                     # lint
uv run mypy .                           # type check
uv run pytest                           # all tests
uv run pytest --cov=activities,workflows,helpers,api --cov-report=term-missing
uv run pytest tests/test_workflow_replay.py -v   # replay/determinism tests
```

## Replay tests

`tests/test_workflow_replay.py` loads fixtures from `tests/fixtures/` and replays through Temporal's `Replayer`. A replay failure = non-deterministic change in workflow code. Regenerate fixtures after intentional workflow changes:
```bash
uv run python tests/generate_fixtures.py
```

## Testing patterns

- HTTP mocked via `respx`
- Activities tested with `ActivityEnvironment`
- Workflow sandbox lines (32-74 in package_triage_workflow.py, etc.) are unreachable from unit tests — covered by replay fixtures instead, not a coverage gap to fix
