# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**dependabot-supply-chain-scout** is a Temporal-based workflow engine that automatically vets Dependabot and Renovate PRs on GitHub repositories. It gathers supply chain risk signals in parallel (PyPI metadata, Socket score, OSV CVEs, package diff, release age, maintainer history), uses Claude to classify risk as green/yellow/red, and acts accordingly: auto-merge low-risk bumps, request review on medium-risk ones, or escalate suspicious ones for human approval.

**Key design principle**: Graceful degradation — works with zero API keys (rule-based, log-only), gets smarter and more actionable as you add them. No config required to try it.

## Project Status

Currently a **Temporal Community experimental project** (not Temporal Inc.). v1 is scoped for PyPI-only; npm support is designed in but implemented in v2.

## Architecture

The system uses a **two-workflow pattern for cross-repo verdict deduplication**:

1. **PackageTriageWorkflow** — gathers signals and classifies risk. Workflow ID: `triage-{ecosystem}-{package}-{new_version}`. Uses `REJECT_DUPLICATE` policy so multiple repos seeing the same version bump share one verdict.

2. **PRActionWorkflow** — handles per-repo actions based on verdict: fetch repo config, call/await PackageTriageWorkflow, decide what to do (auto-merge, request review, post comment, await human decision), and execute. Workflow ID: `pr-action-{repo}-{pr_number}`.

The parent-child relationship uses `ParentClosePolicy.ABANDON` so the package-level triage survives even if one PR's action workflow finishes.

### Signal Flow

```
GitHub webhook → FastAPI receiver → PRActionWorkflow
                                         │
                                         ├─ fetch repo config (.github/triage-agent.yml)
                                         │
                                         ├─ call PackageTriageWorkflow
                                         │   ├─ parallel: fetch PyPI metadata
                                         │   ├─ parallel: Socket score
                                         │   ├─ parallel: OSV CVE check
                                         │   ├─ parallel: package diff
                                         │   ├─ parallel: release age
                                         │   ├─ parallel: maintainer history
                                         │   └─ LLM classify → Verdict
                                         │
                                         └─ act based on verdict + config
                                             ├─ post public comment
                                             ├─ auto-merge (if green + enabled)
                                             ├─ request review (if yellow)
                                             └─ await human signal (if red)
```

### Pydantic Models (activities/models.py)

- **PRContext** — extracted from webhook payload; identifies PR, package, versions, GitHub installation
- **RepoConfig** — loaded from `.github/triage-agent.yml` in target repo; controls per-repo behavior
- **PackageSignals** — collected from parallel activities; fed to LLM
- **Verdict** — LLM output; classification (green/yellow/red), confidence, reasoning, flags

## Development Setup

### Environment

- **Python**: 3.10+
- **Dependency manager**: `uv`
- **Build backend**: `hatchling`
- **Runtime**: Temporal (local dev with `temporal server start-dev`)

### Installation & Running

```bash
# Install dependencies
uv sync

# Start Temporal dev server (in another terminal)
temporal server start-dev

# Run worker
uv run python -m worker

# In another terminal, trigger triage manually for testing
uv run python -m start_workflow --repo owner/repo --package pkg --old-version 1.0.0 --new-version 1.0.1
```

### Linting & Type Checking

```bash
# Format code
uv run ruff format .

# Check formatting
uv run ruff check .

# Type check
uv run mypy .

# All checks together
uv run ruff format --check . && uv run ruff check . && uv run mypy .
```

### Testing

```bash
# Run all tests
uv run pytest

# Run a single test
uv run pytest tests/test_pr_parser.py::test_dependabot_title

# Run with coverage
uv run pytest --cov=activities,workflows,helpers --cov-report=term-missing

# Run replay tests only
uv run pytest tests/test_workflow_replay.py -v
```

### Key Testing Patterns

**Replay tests** (`tests/test_workflow_replay.py`) load committed JSON fixtures from `tests/fixtures/` and replay them through `Replayer` to verify workflow determinism. A replay failure means a non-deterministic change was introduced — the kind of bug that corrupts live workflow state mid-execution.

To regenerate fixtures after an intentional workflow change:
```bash
uv run python tests/generate_fixtures.py
```

Fixtures cover: GREEN auto-merge, YELLOW human-approved, YELLOW human-rejected, RED blocked, and observe-only.

Activity unit tests mock HTTP via `respx`. The `pr_parser` has a corpus of real Dependabot/Renovate PR titles/bodies. Comment formatter is snapshot-tested.

## Code Structure & Patterns

### Directory Layout

```
.
├── worker.py                      # Worker entrypoint
├── start_workflow.py              # CLI starter for manual testing
├── api/
│   └── webhook.py                 # FastAPI GitHub webhook receiver
├── workflows/
│   ├── package_triage_workflow.py  # Signal gathering + LLM classify
│   └── pr_action_workflow.py       # Per-repo action decisions
├── activities/
│   ├── models.py                  # Pydantic v2 models
│   ├── pypi_metadata.py           # PyPI JSON API
│   ├── socket.py                  # Socket.dev OSS API
│   ├── osv.py                     # OSV.dev batch query
│   ├── package_diff.py            # Download & diff sdist/tarball
│   ├── release_age.py             # Hours since publish
│   ├── maintainer.py              # Maintainer set & account age
│   ├── classifier.py              # Claude LLM classification
│   ├── repo_config.py             # Fetch .github/triage-agent.yml
│   └── github.py                  # Comment, merge, label, etc.
├── helpers/
│   ├── prompts.py                 # LLM system prompt
│   ├── comment_formatter.py       # Bot's public PR comment markdown
│   ├── github_app.py              # Installation token resolution
│   └── pr_parser.py               # Extract package/version from PR
└── tests/
    ├── test_workflow_replay.py
    ├── test_activities.py
    ├── test_pr_parser.py
    ├── test_comment_formatter.py
    └── fixtures/
```

### Temporal Conventions

- **Workflow imports**: Use `with workflow.unsafe.imports_passed_through():` for non-deterministic imports
- **Activities by string name**: Reference activities in workflows by string, e.g., `workflow.execute_activity("activities.pypi_metadata.fetch", ...)`. This decouples workflow code from activity imports (key for determinism)
- **Activity naming**: `activities.{module}.{function}`, e.g., `@activity.defn(name="activities.pypi_metadata.fetch")`
- **Data converter**: Worker uses Pydantic v2 data converter
- **Non-retryable errors**: Use `ApplicationError(..., non_retryable=True)` for known-permanent errors (auth failures, 4xx)
- **Retry policies**: Default 5 attempts with 2s initial interval; package_diff allows up to 2min timeout due to network cost

### LLM Integration

**File**: `activities/classifier.py`

Uses Claude API with **tool-use for structured output**:
- Calls `anthropic.AsyncAnthropic()` (set via `ANTHROPIC_MODEL` env var; default: `claude-opus-4-7`)
- Passes `PackageSignals` as JSON, receives `Verdict` via tool schema
- Non-retryable on auth/bad request errors
- System prompt in `helpers/prompts.py` defines GREEN/YELLOW/RED classification logic

The prompt is tuned to be conservative: uncertain between GREEN/YELLOW → choose YELLOW; uncertain between YELLOW/RED → choose YELLOW unless explicit malware indicators.

### GitHub Integration

**Files**: `helpers/github_app.py`, `activities/github.py`

The bot is a GitHub App (installable on any user/org). Each install generates an `installation_id`; for each API call, the bot exchanges the App's JWT for an **installation access token** (valid 1 hour, cached and refreshed).

Activities:
- `comment(pr, verdict)` — posts verdict + signals as markdown table
- `merge_pr(pr)` — squash-merge only if CI passing
- `request_review(pr, reviewers)` — requests reviews from list
- `label(pr, label)` — adds labels (e.g., "supply-chain-suspicious")
- `get_pr(pr)` — fetches current PR state

### Per-Repo Configuration

**File**: `.github/triage-agent.yml` in target repo

Optional YAML file controlling per-repo behavior:
```yaml
auto_merge_enabled: true
auto_merge_classifications: [green]
reviewers: [alice, bob]
min_release_age_hours: 168
block_classifications: [red]
```

**Defaults** (if file missing): observe-only (comment only, never merge/close), no reviewers, 7-day release age. Safe default for freshly-installed bot.

### Signal Activities

- **pypi_metadata.py** — `https://pypi.org/pypi/{package}/{version}/json`; extracts upload time, maintainer, project URLs
- **socket.py** — Socket OSS API; returns score + alerts; designed to accept `ecosystem` parameter for npm compatibility
- **osv.py** — `https://api.osv.dev/v1/query`; batch query; no auth
- **package_diff.py** — Downloads sdist (pip) or tarball (npm); diffs; caps at 100KB; filters noise; prioritizes high-signal files (setup.py, postinstall scripts, package.json)
- **release_age.py** — Hours since publish; <24h is strong yellow/red signal
- **maintainer.py** — Compares maintainer set; tracks publishing account age; first-release-from-new-account is high-signal

All activities handle failures gracefully—missing signals are treated as yellow indicators; never fail the workflow because one signal source is unavailable.

### Webhook Receiver

**File**: `api/webhook.py`

FastAPI handler:
- Verifies HMAC signature using `GITHUB_WEBHOOK_SECRET`
- Filters to `pull_request` events with action in ("opened", "synchronize", "reopened")
- Filters to PRs where `user.login` is `dependabot[bot]` or `renovate[bot]`
- Extracts `installation.id`
- Parses package + versions via `helpers/pr_parser.py`
- Starts `PRActionWorkflow` with `PRContext`
- Returns 200 immediately (async workflow execution)

## Configuration

### Environment Variables (.env)

```
# Temporal
TEMPORAL_ADDRESS=localhost:7233
TEMPORAL_NAMESPACE=default
TEMPORAL_TASK_QUEUE=dependency-triage
TEMPORAL_UI_BASE_URL=http://localhost:8233

# Anthropic
ANTHROPIC_API_KEY=
ANTHROPIC_MODEL=claude-opus-4-7

# GitHub App
GITHUB_APP_ID=
GITHUB_APP_PRIVATE_KEY_PATH=
GITHUB_WEBHOOK_SECRET=

# Socket
SOCKET_API_KEY=

# Operator defaults
DEFAULT_MIN_RELEASE_AGE_HOURS=168
```

Note: Per-repo behavior lives in each repo's `.github/triage-agent.yml`, not `.env`. Operator-level config is for credentials and global defaults only.

## Important Implementation Details

### Cross-Repo Deduplication

The workflow ID for `PackageTriageWorkflow` is `triage-{ecosystem}-{package}-{new_version}` (intentionally omits repo). With `REJECT_DUPLICATE` reuse policy, if a duplicate is started, the caller gets the existing workflow handle and waits on its result. This is a **real superpower**: the verdict is shared across every repo seeing that bump.

### Human-in-the-Loop Pattern

For RED verdicts or when reviewers are configured, the workflow:
1. Posts a public comment with the verdict
2. If RED or needs review: awaits `submit_decision` signal indefinitely
3. Signal handler updates `self._human_decision`
4. Workflow resumes and acts accordingly (merge or close)

This is **durable indefinite wait**—the workflow holds no resources while waiting days for human approval.

### Determinism & Replay Safety

- All non-deterministic I/O (HTTP, LLM calls) happens inside activities
- Workflow code is purely deterministic and replayable
- Activities are isolated; use `@activity.defn(name="...")` for clear naming
- String-based activity references in workflow code decouple workflow from imports

### Building & Deploying

This project is **not yet deployed**. For local dev and testing, use the run sequence above. For v1 deployment, worker will likely be deployed to Fly.io, Railway, or Render pointing at Temporal Cloud or self-hosted Temporal.

## Repo-Specific Notes

This is the **official implementation** of the Dependabot Supply Chain Scout — a standalone, general-purpose tool for OSS maintainers.
