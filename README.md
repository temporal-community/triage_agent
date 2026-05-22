# Dependabot Triage Agent

A durable, supply-chain-aware agent that automatically triages Dependabot and Renovate PRs. It gathers risk signals in parallel (PyPI metadata, OSV CVEs, release age, maintainer history, Socket score, package diff), classifies risk as green/yellow/red, and acts accordingly — posting a verdict comment, requesting review, or auto-merging low-risk bumps.

Built for "cobwebbed" open-source projects drowning in unreviewed dependency PRs, and motivated by active supply chain attack campaigns (Mini Shai-Hulud, May 2026) targeting PyPI packages.

Built on [Temporal](https://temporal.io) to demonstrate durable parallel execution, indefinite human-in-the-loop waits, and cross-repo verdict deduplication.

> **Status:** Experimental. Local testing and personal installs only — not yet deployed as a public GitHub App.

---

## Try it now

No API keys required for a dry run. You only need Python 3.10+, `uv`, and a running Temporal dev server.

```bash
# 1. Clone and install
git clone https://github.com/webchick/triage_agent
cd triage_agent
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
| `ANTHROPIC_API_KEY` + `GITHUB_TOKEN` + `FORCE_AUTO_MERGE=true` | Claude Sonnet 4.6 | Posts comment + merges PR |

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
| Weekly downloads, major bump | pypi.org + pypistats.org | None |
| Known CVEs | api.osv.dev | None |
| Release age | pypi.org | None |
| Maintainer change | pypi.org (compare versions) | None |
| Supply chain score + alerts | api.socket.dev/v0/purl | API key (optional) |
| Package diff | pypi.org sdist download | None |

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
FORCE_AUTO_MERGE=false           # set true to test the merge path locally
```

---

## Why Temporal

This problem is a natural fit for Temporal and the implementation makes that visible:

- **Parallel activities with independent retries** — six signal-gathering API calls run concurrently, each retried independently against flaky third-party APIs.
- **Durable indefinite human-in-the-loop wait** — the workflow sits for days waiting for a human approval signal (`submit_decision`) without holding resources or losing state.
- **Replay-safe LLM calls** — non-determinism is isolated inside activities; workflow code is deterministic and replayable.
- **Workflow-ID-based deduplication across repos** — the same `{package}@{version}` triage runs once globally, shared across every repo seeing that bump. Gets more valuable the more repos use it.

---

## Development

```bash
uv run ruff format .          # format
uv run ruff check .           # lint
uv run mypy .                 # type check
uv run pytest                 # tests
uv run pytest --cov=activities,workflows,helpers --cov-report=term-missing
```

See [CLAUDE.md](CLAUDE.md) for architecture details and [HANDOFF.md](HANDOFF.md) for design rationale and build roadmap.

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
- [ ] GitHub App auth (replaces PAT)
- [ ] FastAPI webhook receiver (live on real Dependabot events)
- [ ] Replay test fixtures
- [ ] Public deployment + GitHub App registration

---

*Experimental project by the [Temporal community](https://github.com/temporal-community). Not an official Temporal Inc. product.*
