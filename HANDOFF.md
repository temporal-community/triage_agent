# Dependabot Triage Agent — Implementation Handoff

## What this is

A Temporal-based agent that automatically triages Dependabot and Renovate PRs on any GitHub repository it's installed on. It gathers supply chain risk signals in parallel (PyPI metadata, Socket score, OSV CVEs, package diff, release age, maintainer history), uses an LLM to classify risk as green/yellow/red, and acts accordingly: auto-merge low-risk bumps, request review on medium-risk ones, escalate suspicious ones for human approval.

The motivating use case is "cobwebbed" open-source projects that have accumulated dozens of unreviewed dependency bump PRs and need help draining the queue safely — especially given the active Mini Shai-Hulud supply chain attacks on PyPI (May 2026). But the design goal is **general purpose**: install on any repo, configure per-repo behavior via a config file in the target repo, and it just works.

## Why Temporal (so you know what to emphasize)

This problem is a natural fit for Temporal and the implementation should make that obvious:

- **Parallel activities with independent retries** — six signal-gathering API calls run concurrently, each retried independently against flaky third-party APIs.
- **Durable indefinite human-in-the-loop wait** — the workflow sits for days waiting for human approval signals without holding resources or losing state.
- **Replay-safe LLM calls** — non-determinism is isolated inside activities; workflow code is deterministic and replayable.
- **Workflow-ID-based deduplication across repos** — the same `{package}@{version}` triage runs once globally and the verdict is shared across every repo seeing that bump. This is a real superpower that gets more valuable the more repos use the bot.

Keep workflow code clean, activities well-isolated. When you have a design choice, pick the one that better showcases Temporal idioms.

## Repo placement

Lives at **`github.com/temporal-community/dependabot-triage-agent`** (experimental-code org, no official approval needed).

A separate, simplified version will later be contributed back to `temporalio/ai-cookbook` as a teaching recipe. **Don't build that simplified version yet** — focus on the standalone, general-purpose tool. The recipe distillation comes after we have something running.

## Style: match existing ai-cookbook recipes

Even though this is its own project, it's built by a Temporal community member and should feel like it could have been a cookbook recipe (scaled up). Match the conventions used in existing recipes — `foundations/hello_world_litellm_python`, `agents/agentic_loop_tool_call_claude_python`, `agents/human_in_the_loop_python`.

### Conventions to follow

- **Flat directory layout by role**, no `src/`. Top-level: `workflows/`, `activities/`, `helpers/`, `api/`, plus `worker.py` and `start_workflow.py` at the repo root.
- **`uv` for dependency management.** `pyproject.toml` uses `hatchling` build backend with explicit packages list: `[tool.hatch.build.targets.wheel] packages = ["activities", "workflows", "helpers", "api"]`.
- **Activities named by module.** E.g. `activities/pypi_metadata.py` containing a function decorated with `@activity.defn(name="activities.pypi_metadata.fetch")`.
- **Models live in `activities/models.py`.** Pydantic v2.
- **Worker uses Pydantic data converter:**
  ```python
  from temporalio.contrib.pydantic import pydantic_data_converter
  client = await Client.connect("localhost:7233", data_converter=pydantic_data_converter)
  ```
- **Workflow file uses `with workflow.unsafe.imports_passed_through():`** for non-deterministic imports.
- **Activities referenced by string name in workflows**, e.g. `workflow.execute_activity("activities.pypi_metadata.fetch", ...)`. Decouples workflow from activity imports.
- **`ApplicationError` with `non_retryable=True`** for known-permanent errors (auth failures, 4xx). See `foundations/hello_world_litellm_python/activities/litellm_completion.py` for the pattern.
- **Separate `start_workflow.py`** as a CLI starter, not bundled with the worker.
- **Run sequence in README**: `temporal server start-dev`, `uv sync`, `uv run python -m worker`, `uv run python -m start_workflow`.

### When in doubt

Look at `foundations/hello_world_litellm_python/` for the basic skeleton, and `agents/human_in_the_loop_python/` for the signal-based human-in-the-loop pattern.

## Architecture

```
Dependabot or Renovate opens a PR
        │
        ▼
GitHub webhook ──► FastAPI receiver
        │              │
        │              ├─ Verify signature
        │              ├─ Filter: PR opened by dependabot[bot] or renovate[bot]
        │              ├─ Resolve GitHub App installation token for source repo
        │              ├─ Parse package + old/new version from PR title/body
        │              └─ Start workflow (ID = f"triage-{ecosystem}-{package}-{new_version}")
        ▼
┌────────────────────────────────────────────────────────────┐
│  DependencyTriageWorkflow                                  │
│                                                            │
│  fetch repo config (.github/triage-agent.yml)              │
│       │                                                    │
│       ▼                                                    │
│  ┌─── parallel signal gathering (activities) ────┐         │
│  │  activities.pypi_metadata.fetch               │         │
│  │  activities.socket.score                      │         │
│  │  activities.osv.check                         │         │
│  │  activities.package_diff.compute              │         │
│  │  activities.release_age.check                 │         │
│  │  activities.maintainer.history                │         │
│  └────────────────────────────────────────────────┘        │
│                       │                                    │
│                       ▼                                    │
│         activities.classifier.classify (LLM)               │
│                       │                                    │
│            ┌──────────┼──────────┐                         │
│            ▼          ▼          ▼                         │
│         GREEN      YELLOW       RED                        │
│            │          │          │                         │
│  per-repo config decides: comment-only, request review,    │
│  auto-merge, or escalate                                   │
│            │          │          │                         │
│            ▼          ▼          ▼                         │
│         await `submit_decision` signal if needed           │
│         (durable, indefinite wait)                         │
│                       │                                    │
│                       ▼                                    │
│              merge or close PR                             │
└────────────────────────────────────────────────────────────┘

Note: The workflow ID intentionally omits the repo. Multiple repos
seeing the same {package}@{version} share one triage workflow and
its verdict, then each gets its own follow-up workflow to actually
act on that verdict for its specific PR.
```

### Two-workflow pattern for cross-repo dedup

To make the cross-repo verdict-sharing work cleanly, split into two workflows:

1. **`PackageTriageWorkflow(ecosystem, package, new_version)`** — does the signal gathering and LLM classification. Workflow ID: `triage-{ecosystem}-{package}-{new_version}`. Reuse policy: `REJECT_DUPLICATE`. If a duplicate is started, the caller gets the existing workflow handle and waits on its result.

2. **`PRActionWorkflow(pr_context)`** — handles per-PR actions: fetch repo config, call/await `PackageTriageWorkflow`, decide what to do based on verdict + repo config, post comment, wait for human if needed, merge or close. Workflow ID: `pr-action-{repo}-{pr_number}`.

The webhook receiver starts `PRActionWorkflow`. That workflow then starts (or attaches to) `PackageTriageWorkflow` via `start_child_workflow` or `execute_child_workflow` with a parent close policy of `ABANDON` (so the package-level triage survives even if one PR's action workflow finishes). The verdict is cached in the package workflow's result.

This is the kind of structure that demonstrates Temporal idioms well and is worth a section in the README.

## Project layout

```
dependabot-triage-agent/
├── README.md
├── pyproject.toml
├── .env.example
├── .gitignore
├── .github/workflows/ci.yml
├── worker.py
├── start_workflow.py            # CLI to trigger triage manually for testing
├── api/
│   ├── __init__.py
│   └── webhook.py               # FastAPI GitHub webhook receiver
├── workflows/
│   ├── __init__.py
│   ├── package_triage_workflow.py
│   └── pr_action_workflow.py
├── activities/
│   ├── __init__.py
│   ├── models.py                # PackageSignals, Verdict, PRContext, RepoConfig
│   ├── pypi_metadata.py
│   ├── socket.py
│   ├── osv.py
│   ├── package_diff.py
│   ├── release_age.py
│   ├── maintainer.py
│   ├── classifier.py            # LLM classification
│   ├── repo_config.py           # fetches .github/triage-agent.yml from target repo
│   └── github.py                # comment, merge, request_review, label, get_pr
├── helpers/
│   ├── __init__.py
│   ├── prompts.py               # classifier system prompt
│   ├── comment_formatter.py     # builds the bot's PR comment markdown
│   ├── github_app.py            # installation token resolution
│   └── pr_parser.py             # extract package/version from Dependabot/Renovate PRs
└── tests/
    ├── test_workflow_replay.py
    ├── test_activities.py
    ├── test_pr_parser.py
    ├── test_comment_formatter.py
    └── fixtures/
```

## Models

Pydantic v2:

```python
from pydantic import BaseModel
from typing import Literal

class PRContext(BaseModel):
    repo: str                         # "owner/name"
    pr_number: int
    pr_author: str                    # "dependabot[bot]" or "renovate[bot]"
    installation_id: int              # GitHub App installation
    ecosystem: Literal["pip", "npm"]  # npm is v2; pip-only for v1
    package_name: str
    old_version: str
    new_version: str

class RepoConfig(BaseModel):
    """Loaded from .github/triage-agent.yml in target repo. All fields optional."""
    auto_merge_enabled: bool = False
    reviewers: list[str] = []
    min_release_age_hours: int = 168       # 7 days
    allowed_ecosystems: list[str] = ["pip", "npm"]
    auto_merge_classifications: list[str] = ["green"]  # could expand to ["green", "yellow"]
    block_classifications: list[str] = []  # e.g. ["red"] to force-close suspicious PRs

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
```

Refine as you discover what signal sources actually return; document additions in the model docstring. **Design activity interfaces so they're ecosystem-agnostic where possible** — the npm equivalents of PyPI/OSV/Socket lookups should slot in without changing the workflow.

## Per-repo configuration

A repo opts into the bot's behavior via `.github/triage-agent.yml` committed in its own root:

```yaml
# .github/triage-agent.yml
auto_merge_enabled: true
auto_merge_classifications: [green]
reviewers: [alice, bob]
min_release_age_hours: 168
block_classifications: [red]
```

If the file is missing, **defaults apply**: observe-only (comment only, never merge or close), no reviewers, 7-day release age threshold. This is the safe default for a freshly-installed bot.

The `activities/repo_config.py` activity fetches and parses this file. Cache the result for the duration of one workflow run (don't re-fetch for each decision point); don't cache across runs (config can change).

This pattern (config-in-repo) is how Renovate, Mergify, and Dependabot itself work. It scales cleanly to "anyone can install this on their repo" without requiring access to the bot's central config.

## GitHub App, multi-installation

The bot is a GitHub App, installable on any user or org account. Implementation notes:

- One App registration → one App ID + one private key (held by the bot operator)
- Each install on a repo or org generates an `installation_id` GitHub sends with every webhook
- For each API call (merge, comment, etc.) the bot must exchange the App's JWT for an **installation access token** scoped to that installation, then use it for that call
- `helpers/github_app.py` handles JWT generation and installation token caching (tokens are valid for 1 hour; cache and refresh)
- Each GitHub action activity takes `installation_id` as an argument and resolves the token inside

The webhook handler reads `installation.id` from the webhook payload and stuffs it into `PRContext` so downstream activities can use it.

Recommended library: `PyGithub` supports App auth, or use raw `httpx` + `PyJWT` for tighter control. Either is fine.

## Workflow sketch

```python
# workflows/pr_action_workflow.py
from datetime import timedelta
from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.workflow import ParentClosePolicy

with workflow.unsafe.imports_passed_through():
    from activities.models import PRContext, RepoConfig, Verdict
    from workflows.package_triage_workflow import PackageTriageWorkflow


@workflow.defn
class PRActionWorkflow:
    def __init__(self):
        self._human_decision: str | None = None

    @workflow.signal
    def submit_decision(self, decision: str):
        self._human_decision = decision

    @workflow.query
    def status(self) -> dict:
        return {"awaiting_human": self._human_decision is None}

    @workflow.run
    async def run(self, pr: PRContext) -> str:
        retry = RetryPolicy(maximum_attempts=5, initial_interval=timedelta(seconds=2))
        opts = dict(start_to_close_timeout=timedelta(seconds=30), retry_policy=retry)

        config: RepoConfig = await workflow.execute_activity(
            "activities.repo_config.fetch", pr, **opts)

        # Get or share the package-level triage (cross-repo dedup)
        verdict: Verdict = await workflow.execute_child_workflow(
            PackageTriageWorkflow.run,
            args=[pr.ecosystem, pr.package_name, pr.old_version, pr.new_version],
            id=f"triage-{pr.ecosystem}-{pr.package_name}-{pr.new_version}",
            parent_close_policy=ParentClosePolicy.ABANDON,
        )

        # Always post a comment with the verdict
        await workflow.execute_activity(
            "activities.github.comment", args=[pr, verdict], **opts)

        # Block path
        if verdict.classification in config.block_classifications:
            await workflow.execute_activity(
                "activities.github.label",
                args=[pr, "supply-chain-suspicious"], **opts)
            return f"blocked-{verdict.classification}"

        # Auto-merge path
        if (config.auto_merge_enabled
                and verdict.classification in config.auto_merge_classifications):
            await workflow.execute_activity(
                "activities.github.merge_pr", args=[pr], **opts)
            return "auto-merged"

        # Human-review path
        if config.reviewers:
            await workflow.execute_activity(
                "activities.github.request_review",
                args=[pr, config.reviewers], **opts)

        await workflow.wait_condition(lambda: self._human_decision is not None)

        if self._human_decision == "approve":
            await workflow.execute_activity(
                "activities.github.merge_pr", args=[pr], **opts)
            return "human-approved-merged"
        return "human-rejected"
```

```python
# workflows/package_triage_workflow.py
import asyncio
from datetime import timedelta
from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from activities.models import PackageSignals, Verdict


@workflow.defn
class PackageTriageWorkflow:
    @workflow.run
    async def run(self, ecosystem: str, package: str,
                  old_version: str, new_version: str) -> Verdict:
        retry = RetryPolicy(maximum_attempts=5, initial_interval=timedelta(seconds=2))
        opts = dict(start_to_close_timeout=timedelta(seconds=30), retry_policy=retry)

        args = [ecosystem, package, old_version, new_version]
        pypi, socket, osv, diff, maint, age = await asyncio.gather(
            workflow.execute_activity("activities.pypi_metadata.fetch", args=args, **opts),
            workflow.execute_activity("activities.socket.score", args=args, **opts),
            workflow.execute_activity("activities.osv.check", args=args, **opts),
            workflow.execute_activity("activities.package_diff.compute", args=args,
                start_to_close_timeout=timedelta(minutes=2), retry_policy=retry),
            workflow.execute_activity("activities.maintainer.history", args=args, **opts),
            workflow.execute_activity("activities.release_age.check", args=args, **opts),
        )
        signals = PackageSignals(
            ecosystem=ecosystem, package_name=package,
            old_version=old_version, new_version=new_version,
            **{**pypi, **socket, **osv, **diff, **maint, **age},
        )
        return await workflow.execute_activity(
            "activities.classifier.classify", signals,
            start_to_close_timeout=timedelta(seconds=60), retry_policy=retry,
        )
```

## Webhook receiver

`api/webhook.py`:
- Verify HMAC signature using `GITHUB_WEBHOOK_SECRET`
- Filter to `pull_request` events with `action in ("opened", "synchronize", "reopened")`
- Filter to PRs where `user.login` is `dependabot[bot]` or `renovate[bot]`
- Extract `installation.id` from payload
- Parse package + versions via `helpers/pr_parser.py`:
  - Dependabot PR titles look like: `Bump litellm from 1.30.1 to 1.30.2 in /foundations/hello_world_litellm_python`
  - Renovate PR titles look like: `Update dependency litellm to v1.30.2` (or grouped)
  - Both bots also embed structured data in the PR body — Dependabot has a YAML block, Renovate has an HTML comment with metadata. Parse from body where available; fall back to title regex.
- Start `PRActionWorkflow` with the constructed `PRContext`
- Return 200 immediately (don't await workflow)

`helpers/pr_parser.py` is worth unit-testing thoroughly. PR title formats are surprisingly varied across grouped updates, security updates, lockfile-only updates, etc. Start with the common shapes; handle edge cases as they come up.

## Signal sources — implementation notes

**`activities/pypi_metadata.py`** — Hit `https://pypi.org/pypi/{package}/{version}/json`. Extract upload time, maintainer info, project URLs. No auth needed. Wrap 404s as `non_retryable` `ApplicationError`.

**`activities/socket.py`** — Socket has a free API for OSS. Sign up at socket.dev, hit their REST API. Handle 404 gracefully (return `socket_score=None, socket_alerts=[]`). Document `SOCKET_API_KEY` in `.env.example`. Socket supports both pip and npm — design the activity to take `ecosystem` as input.

**`activities/osv.py`** — OSV.dev batch query at `https://api.osv.dev/v1/query`. No auth. Pass ecosystem as `PyPI` or `npm`.

**`activities/package_diff.py`** — Trickiest. Download sdist (or npm tarball) for both versions, extract, diff:
- For pip: sdist URL is in PyPI JSON metadata
- For npm: tarball URL is in npm registry metadata at `https://registry.npmjs.org/{package}/{version}`
- Don't shell out — use `httpx` + `tarfile`/`zipfile` directly
- If sdist unavailable, fall back to wheel/npm file-list diff
- Cap diff size at 100KB; if larger return `"diff too large"` + the size. Don't feed 5MB to the LLM.
- Filter out noise: `.dist-info/RECORD`, generated files, lockfiles
- **Always include**: `setup.py`, `setup.cfg`, `pyproject.toml`, any `__init__.py`, `package.json`, postinstall scripts, any new file. These are the highest-signal targets for Shai-Hulud-style attacks.

**`activities/release_age.py`** — Hours since publish from registry metadata. <24h is a strong yellow/red signal given active campaigns.

**`activities/maintainer.py`** — Compare maintainer set between old and new version metadata. Track publishing account age. First-release-from-new-account is high-signal.

**For all signal activities**: handle failures gracefully. If Socket is down, return `None`/empty. The LLM prompt treats missing signals as a yellow indicator. Never fail the whole workflow because one signal source is unavailable.

## LLM classifier

Use the Anthropic SDK with tool-use for structured output. See `agents/agentic_loop_tool_call_claude_python` for the cookbook pattern.

```python
# activities/classifier.py
import os
import anthropic
from temporalio import activity
from temporalio.exceptions import ApplicationError

from activities.models import PackageSignals, Verdict
from helpers.prompts import CLASSIFIER_SYSTEM


@activity.defn(name="activities.classifier.classify")
async def classify(signals: PackageSignals) -> Verdict:
    client = anthropic.AsyncAnthropic()
    try:
        response = await client.messages.create(
            model=os.environ.get("ANTHROPIC_MODEL", "claude-opus-4-7"),
            max_tokens=1024,
            system=CLASSIFIER_SYSTEM,
            messages=[{
                "role": "user",
                "content": f"Signals:\n{signals.model_dump_json(indent=2)}",
            }],
            tools=[{
                "name": "submit_verdict",
                "description": "Submit your risk classification",
                "input_schema": Verdict.model_json_schema(),
            }],
            tool_choice={"type": "tool", "name": "submit_verdict"},
        )
    except anthropic.AuthenticationError as exc:
        raise ApplicationError(str(exc), type="AuthenticationError",
                               non_retryable=True) from exc
    except anthropic.BadRequestError as exc:
        raise ApplicationError(str(exc), type="BadRequestError",
                               non_retryable=True) from exc

    tool_use = next(b for b in response.content if b.type == "tool_use")
    return Verdict(**tool_use.input)
```

### System prompt outline (`helpers/prompts.py`)

```
You are a supply chain security analyst reviewing a dependency version
bump. Given structured signals about the package and version, classify
the risk as GREEN, YELLOW, or RED.

GREEN — routine bump. ALL of:
  - patch or minor version bump
  - well-established package (>10k weekly downloads)
  - no Socket alerts
  - no CVEs
  - release age > 7 days
  - no maintainer changes
  - diff is small and looks like normal dev work

YELLOW — needs human eyes. ANY of:
  - major version bump
  - release age < 7 days
  - diff unusually large for the version delta
  - new maintainer in last 90 days
  - Socket informational alerts
  - low download count (<1000/week)
  - missing signals (Socket unavailable, etc.)

RED — likely supply chain attack. ANY of:
  - install scripts added or modified (setup.py, postinstall hooks)
  - obfuscated code, base64 blobs, hex-encoded strings
  - exec/eval on dynamic strings
  - network calls to unexpected domains
  - filesystem access to credentials paths (~/.npmrc, ~/.aws, etc.)
  - recent maintainer takeover signal
  - Socket critical alerts
  - version <24h old with unusual diff content

Be conservative. When uncertain between GREEN and YELLOW, choose YELLOW.
When uncertain between YELLOW and RED, choose YELLOW unless there are
explicit malware indicators.

Cite specific signal values in your reasoning. Reference the diff when
relevant.
```

Tune iteratively. First version doesn't need to be perfect.

## GitHub action activities

`activities/github.py`:
- `comment(pr, verdict)` — post comment with verdict + signals as markdown table
- `merge_pr(pr)` — squash-merge, only if CI is passing (check via `/repos/{owner}/{repo}/commits/{sha}/check-runs`)
- `request_review(pr, reviewers)` — request reviews from the configured list
- `label(pr, label)` — add labels
- `get_pr(pr)` — fetch current PR state (for status checks before merge)

All take `pr: PRContext` so they can resolve the installation token from `pr.installation_id`.

The bot comment is **public documentation** — the thing every user of every repo sees. Make it look good. Put formatting in `helpers/comment_formatter.py` and snapshot-test it. Include:
- Verdict badge (color + emoji)
- Confidence
- Markdown table of key signals
- Reasoning quote from the LLM
- Flags
- Link to the workflow run in Temporal UI (`TEMPORAL_UI_BASE_URL`)
- Link to repo's `.github/triage-agent.yml` so users know how to configure behavior

## Configuration (`.env.example`)

```
# Temporal
TEMPORAL_ADDRESS=localhost:7233
TEMPORAL_NAMESPACE=default
TEMPORAL_TASK_QUEUE=dependency-triage
TEMPORAL_UI_BASE_URL=http://localhost:8233

# Anthropic
ANTHROPIC_API_KEY=
ANTHROPIC_MODEL=claude-opus-4-7

# GitHub App (operator-side; one set for the whole deployment)
GITHUB_APP_ID=
GITHUB_APP_PRIVATE_KEY_PATH=
GITHUB_WEBHOOK_SECRET=

# Socket
SOCKET_API_KEY=

# Operator defaults (override per-repo via .github/triage-agent.yml)
DEFAULT_MIN_RELEASE_AGE_HOURS=168
```

Note: per-repo behavior (auto-merge, reviewers, etc.) lives in each repo's `.github/triage-agent.yml`, not in `.env`. Operator-level config in `.env` is for credentials and global defaults only.

## pyproject.toml

```toml
[project]
name = "dependabot-triage-agent"
version = "0.1.0"
description = "Durable Dependabot/Renovate PR triage agent built on Temporal"
readme = "README.md"
requires-python = ">=3.10"
dependencies = [
    "temporalio>=1.12.0",
    "anthropic>=0.40.0",
    "httpx>=0.28.0",
    "pydantic>=2.0",
    "fastapi>=0.115.0",
    "uvicorn>=0.34.0",
    "python-dotenv>=1.0.0",
    "PyGithub>=2.5.0",
    "PyJWT>=2.8.0",
    "cryptography>=42.0",
    "pyyaml>=6.0",
]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["activities", "workflows", "helpers", "api"]

[dependency-groups]
dev = [
    "pytest>=8.0",
    "pytest-asyncio>=0.23",
    "respx>=0.21",
    "ruff>=0.5",
    "mypy>=1.10",
]
```

## Testing

**Replay test is the headline** — Temporal's superpower for AI workflows.

```python
# tests/test_workflow_replay.py
import pytest
from temporalio.worker import Replayer
from workflows.pr_action_workflow import PRActionWorkflow
from workflows.package_triage_workflow import PackageTriageWorkflow

@pytest.mark.asyncio
async def test_replay_green_path():
    replayer = Replayer(workflows=[PRActionWorkflow, PackageTriageWorkflow])
    await replayer.replay_workflow(load_history("fixtures/green_automerge.json"))
```

Record histories for:
- GREEN auto-merge
- YELLOW human-approved
- YELLOW human-rejected
- RED block (with `block_classifications: [red]` config)
- Observe-only mode (no config file, defaults apply)

Also:
- Activity unit tests with mocked HTTP via `respx`
- `pr_parser` tests against a corpus of real Dependabot and Renovate PR titles/bodies
- Snapshot test for the comment formatter
- Integration test against `temporalio.testing.WorkflowEnvironment` with mocked external APIs

## CI

`.github/workflows/ci.yml`:
- `uv sync`
- `uv run ruff check` + `uv run ruff format --check`
- `uv run mypy .`
- `uv run pytest`

## README structure

1. **What it does** — one paragraph, mention Shai-Hulud context, mention "for cobwebbed repos"
2. **Install on your repo** — primary install path. GitHub App install link, optional `.github/triage-agent.yml` config example, defaults explained.
3. **Live demo** — link to public repos where the bot is running, screenshot of a real comment
4. **How it works** — architecture diagram + a few lines on each phase. Highlight cross-repo verdict dedup.
5. **Configuration reference** — full `.github/triage-agent.yml` schema with all options
6. **Running your own instance** — for users who want to self-host instead of using the public bot. Worker deploy, env vars, webhook setup.
7. **Tuning the classifier** — how to adjust the prompt and thresholds
8. **Why Temporal** — the four bullets from the "Why Temporal" section
9. **Status** — experimental, run by @temporal-community, not Temporal Inc.

Embed a screenshot of a real bot comment.

## Build order

1. Stub workflows + activities with hardcoded fake signals. Get end-to-end Temporal shape working with worker, `start_workflow.py`, assertions on the verdict path. **Build both workflows (Package + PRAction) from the start** — the dedup pattern is core, not an add-on.
2. Replace fake signals with real PyPI + OSV (both free, no auth).
3. Add Socket integration (requires API key signup).
4. Add `package_diff` activity — hardest, its own iteration.
5. Wire in LLM classifier with structured-output tool-use.
6. Implement `repo_config.fetch` activity + GitHub App installation token resolution.
7. Build FastAPI webhook receiver and the `pr_parser` for Dependabot + Renovate.
8. Build GitHub action activities (comment, merge, label, etc.).
9. Deploy worker (Fly.io / Railway / Render / VM) pointing at Temporal Cloud or self-hosted Temporal.
10. Register GitHub App publicly (so anyone can install) **in observe-only defaults** (no auto-merge unless repo opts in via config).
11. First test deployment: install on a personal test repo and a friendly maintainer's repo. Watch it triage real PRs.
12. Install on `temporalio/ai-cookbook` as the high-visibility reference deployment.
13. Tune prompt based on what it gets wrong. Encourage adopters to PR config tweaks back.
14. README, screenshots, v0.1.0 tag.

v1 doesn't need to be production-perfect. Optimize for getting it installed on real repos quickly so we can iterate against reality.

## Out of scope for v1

- **npm support** — design models and activity interfaces to accept it cleanly, but scope implementation to v2. PyPI-only for v1.
- **Web dashboard** — GitHub PR comments + Temporal UI are the dashboard
- **Custom rules engine** — for v1, the LLM prompt is the rule engine. A YAML-based rules DSL could come later if needed.
- **Auto-rebase on conflict** — let Dependabot/Renovate handle that on their own cadence

## Questions to surface (don't guess)

- Exact model to use (`claude-opus-4-7` is a placeholder)
- Worker deploy target (Temporal Cloud vs self-hosted; hosting platform)
- Whether to register the GitHub App publicly from the start, or start with private/personal install and go public after dogfooding
- Default reviewers behavior when no config file is present — currently spec says "no reviewers" but could alternatively be "the repo owner"
