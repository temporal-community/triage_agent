# Dependabot Supply Chain Scout

A supply-chain-aware bot that automatically vets Dependabot and Renovate PRs before they merge. It scouts six independent risk signals in parallel — PyPI metadata, OSV CVEs, Socket score, package diff, release age, maintainer history — classifies risk as green/yellow/red, and acts accordingly: posting a verdict comment, requesting review, or auto-merging low-risk bumps.

Gives every dependency PR a careful second opinion, whether your repo is actively maintained or sitting on a backlog of unreviewed bumps.

> **Status:** Experimental. Local testing and personal installs only — not yet deployed as a public GitHub App.

---

## Try it now

No API keys required for a dry run. You only need Python 3.10+, `uv`, and a running Temporal dev server.

```bash
# 1. Clone and install
git clone https://github.com/webchick/dependabot-supply-chain-scout
cd dependabot-supply-chain-scout
uv sync

# 2. Start Temporal dev server (separate terminal)
temporal server start-dev

# 3. Start the worker (separate terminal)
uv run python -m worker

# 4. Triage a real Dependabot PR
uv run python -m start_workflow \
  --repo temporalio/ai-cookbook \
  --package idna \
  --old-version 3.11 \
  --new-version 3.15 \
  --pr-number 122
```

Open the Temporal UI at **http://localhost:8233** to watch the workflow run — six signal activities fan out in parallel, the classifier returns a verdict, and the agent logs what it would do.

### Capability tiers

The agent degrades gracefully based on which keys you provide:

| Keys set | Classifier | GitHub actions |
|---|---|---|
| _(none)_ | Rule-based (CVE thresholds, release age, download count) | Log-only — prints what it would do |
| `ANTHROPIC_API_KEY` | Claude Sonnet 4.6 via tool-use | Log-only |
| `ANTHROPIC_API_KEY` + `GITHUB_TOKEN` + `ENABLE_PR_ACTIONS=true` | Claude Sonnet 4.6 | Posts comment + merges PR |

Copy `.env.example` to `.env` and fill in the keys you have.

---

## How it works

### Two-workflow pattern for cross-repo deduplication

The agent splits into two Temporal workflows:

**`PackageTriageWorkflow`** — gathers signals and classifies risk. Workflow ID: `triage-{ecosystem}-{package}-{new_version}`. Uses `REJECT_DUPLICATE` reuse policy, so if ten repos all see `idna` bump to 3.15 at the same time, signal gathering and LLM classification run **once** and the verdict is shared across all of them.

**`PRActionWorkflow`** — handles per-repo actions: fetch repo config, await the package triage verdict, then decide what to do based on verdict + config (comment, auto-merge, request review, or escalate for human approval). Workflow ID: `pr-action-{repo}-{pr_number}`.

```
GitHub webhook → FastAPI receiver → PRActionWorkflow
                                         │
                                         ├─ fetch .github/triage-agent.yml
                                         │
                                         ├─ PackageTriageWorkflow (shared across repos)
                                         │   ├─ parallel: PyPI metadata
                                         │   ├─ parallel: Socket score
                                         │   ├─ parallel: OSV CVE check
                                         │   ├─ parallel: package diff
                                         │   ├─ parallel: release age
                                         │   ├─ parallel: maintainer history
                                         │   └─ LLM classify → Verdict
                                         │
                                         └─ act: comment / auto-merge / request review / escalate
```

### Signal sources

| Signal | API | Auth |
|---|---|---|
| Package description, weekly downloads, major bump | pypi.org + pypistats.org | None |
| Known CVEs | api.osv.dev | None |
| Release age | pypi.org | None |
| Maintainer change | pypi.org (compare versions) | None |
| Supply chain score + alerts | api.socket.dev/v0/purl | API key (optional) |
| Package diff | pypi.org sdist download | None |

The package description (from PyPI's `info.summary`) is passed to the classifier to help it calibrate risk thresholds. A package that touches auth, cryptography, or network I/O warrants tighter scrutiny than a color-formatting utility — without needing a hardcoded "critical packages" list that goes stale.

### Classifier

With `ANTHROPIC_API_KEY`: calls Claude Sonnet 4.6 via tool-use for structured output. The system prompt is conservative — uncertain between GREEN/YELLOW → YELLOW; uncertain between YELLOW/RED → YELLOW unless explicit malware indicators.

Without `ANTHROPIC_API_KEY`: rule-based fallback using signal thresholds (CVEs → RED; major bump / fresh release / maintainer change → YELLOW; otherwise GREEN).

---

## Per-repo configuration

Repos control the agent's behavior via `.github/triage-agent.yml` committed in their own root:

```yaml
# .github/triage-agent.yml
auto_merge_enabled: true
auto_merge_classifications: [green]
reviewers: [alice, bob]          # request review on yellow
min_release_age_hours: 168       # 7 days
block_classifications: [red]     # add label + block on red
```

**If the file is missing, the agent runs in observe-only mode** — it posts a verdict comment but never merges, closes, or requests review. Safe default for new installs.

---

## Environment variables

```bash
# Temporal
TEMPORAL_ADDRESS=localhost:7233
TEMPORAL_NAMESPACE=default
TEMPORAL_TASK_QUEUE=dependency-triage
TEMPORAL_UI_BASE_URL=http://localhost:8233

# Anthropic (optional — enables LLM classifier)
ANTHROPIC_API_KEY=
ANTHROPIC_MODEL=claude-sonnet-4-6

# GitHub (optional — enables real PR comments and merges)
GITHUB_TOKEN=                    # PAT for local testing
# GitHub App (production — replaces GITHUB_TOKEN)
GITHUB_APP_ID=
GITHUB_APP_PRIVATE_KEY_PATH=
GITHUB_WEBHOOK_SECRET=

# Socket (optional — enables supply chain score signal)
SOCKET_API_KEY=

# Local testing
ENABLE_PR_ACTIONS=false          # set true to enable real PR comments + merges locally
```

---

## Why Temporal

This problem is a natural fit for Temporal and the implementation makes that visible:

- **Parallel activities with independent retries** — six signal-gathering API calls run concurrently, each retried independently against flaky third-party APIs.
- **Durable indefinite human-in-the-loop wait** — the workflow sits for days waiting for a human approval signal (`submit_decision`) without holding resources or losing state.
- **Replay-safe LLM calls** — non-determinism is isolated inside activities; workflow code is deterministic and replayable.
- **Workflow-ID-based deduplication across repos** — the same `{package}@{version}` triage runs once globally, shared across every repo seeing that bump. Gets more valuable the more repos use it.

---

## Running the webhook receiver

To receive live GitHub events locally, run the FastAPI server alongside the worker and expose it with [ngrok](https://ngrok.com):

```bash
# Terminal 1 — Temporal dev server
temporal server start-dev

# Terminal 2 — worker
uv run python -m worker

# Terminal 3 — webhook receiver
uv run uvicorn api.webhook:app --port 8080

# Terminal 4 — expose to GitHub
ngrok http 8080
```

Then in your GitHub repo settings → Webhooks:
- **Payload URL**: `https://<your-ngrok-id>.ngrok.io/webhook`
- **Content type**: `application/json`
- **Secret**: value of `GITHUB_WEBHOOK_SECRET` in your `.env`
- **Events**: select *Pull requests* only

---

## Development

```bash
uv run ruff format .          # format
uv run ruff check .           # lint
uv run mypy .                 # type check
uv run pytest                 # tests
uv run pytest --cov=activities,workflows,helpers --cov-report=term-missing
```

### Replay tests — how the agent stays trustworthy

`tests/test_workflow_replay.py` loads committed JSON fixtures from `tests/fixtures/` and replays them through Temporal's `Replayer`. A replay failure means the workflow code became non-deterministic — the kind of silent breakage that corrupts live workflow state mid-execution without any obvious error.

This is the answer to "how do I know a prompt change didn't break real-PR behavior?" The fixtures capture actual execution histories (GREEN auto-merge, YELLOW human-approved, YELLOW human-rejected, RED blocked, observe-only). If your change passes unit tests but breaks replay, Temporal would have crashed on a live workflow.

To regenerate fixtures after an intentional workflow change:
```bash
uv run python tests/generate_fixtures.py
```

See [CLAUDE.md](CLAUDE.md) for architecture details.

---

## Roadmap

- [x] Two-workflow Temporal shape (PackageTriageWorkflow + PRActionWorkflow)
- [x] Real PyPI, OSV, release age, maintainer signals
- [x] LLM classifier with rule-based fallback
- [x] Real GitHub comment + merge via PAT
- [x] Graceful degradation (zero-key dry run)
- [x] Socket.dev integration
- [x] Package diff activity (sdist download + diff)
- [x] Per-repo config fetched from `.github/triage-agent.yml`
- [x] GitHub App auth (replaces PAT)
- [x] FastAPI webhook receiver (live on real Dependabot events)
- [x] Replay test fixtures
- [ ] Public deployment + GitHub App registration

---

*Built with [Temporal](https://temporal.io) for durable, crash-proof workflow execution.*
