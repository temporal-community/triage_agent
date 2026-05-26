# Dependency Scout

You have 47 unreviewed Dependabot PRs. It’s midnight, CI is green, and you’ve merged dozens of these before. And yet...

Maintainers aren’t careless — they’re exhausted. And modern supply-chain attacks are specifically designed to slip past smart, well-intentioned humans doing their best under impossible workloads.

**This tool gives every dependency PR a data-backed second opinion before it merges.**

**What it checks:**
- **Known vulnerabilities** — [OSV](https://osv.dev) database (includes [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages))
- **Supply chain score** — [Socket.dev](https://socket.dev) for obfuscated code, install-time scripts, typosquatting
- **What code actually changed** — diffs the package archives; flags new binaries, new install hooks, network calls, obfuscated code, git-URL dependencies
- **Release freshness** — flags releases under 24h ("very fresh") or 7 days ("recent"); won't auto-merge anything under 7 days by default
- **Maintainer changes** — a new account publishing a popular package is a classic attack vector
- **Build provenance** — [SLSA](https://slsa.dev) attestations; flags dropped tag signing and re-release patterns
- **Repo health** — [OpenSSF Scorecard](https://securityscorecards.dev) for dangerous CI workflows, overprivileged tokens, maintenance status
- **Zombie packages** — deprecated packages and patches to abandoned major version lines
- **Suspicious PR files** — CI scripts or Dockerfiles in a "routine dep bump" are a red flag

Classifies GREEN / YELLOW / RED, posts a comment explaining its reasoning, and takes action based on your config (or nothing if you haven't configured anything).

> **Status:** Experimental — self-hosted, bring your own keys. No shared infrastructure, no accounts, no sign-up.

---

## Try it on one PR right now

No server setup needed. Point it at any GitHub PR and it'll run all 11 checks and print a verdict:

```bash
git clone https://github.com/temporal-community/dependency-scout
cd dependency-scout
uv run python triage.py https://github.com/temporalio/ai-cookbook/pull/127
```

```
Running the following checks:

  ✓  Core checks  OSV, diff analysis, release age, maintainer history, version lineage, and more
  ℹ  Socket.dev   Supply-chain threat intelligence — add SOCKET_API_KEY to .env  (socket.dev)
  ✓  Classifier   Anthropic — LLM-powered GREEN/YELLOW/RED verdict

  See docs/configuration.md for setup details.

────────────────────────────────────────────────────────────

Triaging actions/checkout  4 → 6  (github_actions)

  metadata         ─  N/A — no download data for this ecosystem
  osv              ✓  no known vulnerabilities
  diff             ✓  no suspicious patterns
  maintainer       ✓  no changes detected
  age              ✓  released 3273h ago
  attestation      ─  N/A — no build provenance
  release_notes    ─  N/A — no GitHub release
  version_lineage  ✓  on latest version line
  deps_dev         ✓  not deprecated
  scorecard        ─  N/A — not in Scorecard database

Verdict: 🟡 YELLOW  (confidence 82%)

  This is a major version bump (v4 → v6) for `actions/checkout`, one of the most
  widely used GitHub Actions. Several signals warrant human review:

  ⚠ major_version_bump
  ⚠ large_diff_for_version_delta
  ⚠ network_calls_in_lib
  ⚠ security_sensitive_credential_handling_refactored
  ⚠ new_outbound_data_in_http_user_agent
  ⚠ version_tag_vs_package_json_discrepancy

────────────────────────────────────────────────────────────
dependency-scout  ·  docs/deployment.md  ·  temporal.io
────────────────────────────────────────────────────────────
```

Or pass the details explicitly:

```bash
uv run python triage.py --ecosystem pip --package requests --old 2.31.0 --new 2.32.3
```

Set `ANTHROPIC_API_KEY` in `.env` for Claude classification; without it, the rule-based classifier runs entirely locally. Set `GITHUB_TOKEN` for higher API rate limits and private repos.

When you want this to run **automatically on every PR** — with retry, the human-approval loop, and optional auto-merge — read on.

---

## Full automated setup (5 minutes)

You need Python 3.10+, [`uv`](https://docs.astral.sh/uv/), and the [Temporal CLI](https://docs.temporal.io/cli).

```bash
git clone https://github.com/temporal-community/dependency-scout
cd dependency-scout
uv run python setup.py
```

The setup script checks prerequisites, explains the tradeoffs between a PAT and a GitHub App, lets you choose your LLM (Claude, OpenAI, Ollama, or skip), writes `.env`, and prints the repo config snippet to paste into your target repo.

The Temporal dev server runs entirely on your machine — no account or payment needed.

Then:

```bash
# Terminal 1 — Temporal dev server (runs in memory on your machine — no sign-up, no payment)
temporal server start-dev

# Terminal 2 — Scout worker (picks up triage jobs and runs the analysis)
uv run python -m worker

# Test a triage run against a real public package (no API keys needed)
uv run python -m start_workflow \
  --repo temporalio/ai-cookbook \
  --package idna \
  --old-version 3.11 \
  --new-version 3.15 \
  --pr-number 122
```

Open **http://localhost:8233** to watch the workflow run in the Temporal UI. No API keys needed — it'll use the rule-based classifier and log what it would do without touching the actual PR.

### What each credential unlocks

| Configured | What changes |
|---|---|
| _(none)_ | Rule-based classifier, log-only output |
| `ANTHROPIC_API_KEY` | Claude classifies (set `ANTHROPIC_MODEL` to pin a version) |
| `OPENAI_API_KEY` + `OPENAI_MODEL` | OpenAI classifies instead |
| `OLLAMA_HOST` + `OLLAMA_MODEL` | Local Ollama classifies — free, no data leaves your machine |
| `CLASSIFIER=rule_based` | Force rule-based even when an LLM key is present |
| `GITHUB_TOKEN` or GitHub App | Posts real PR comments on GitHub |
| `GITLAB_TOKEN` | Posts real MR comments on GitLab |
| `ENABLE_PR_ACTIONS=true` | Can automatically merge GREEN PRs and/or close RED ones |
| `SOCKET_API_KEY` | Adds Socket.dev supply-chain score check |

Copy `.env.example` to `.env` and fill in what you have, or run `uv run python setup.py` to be walked through it interactively.

---

## Configuring your repo

Add `.github/dependency-scout.yml` to any repo where you want the Scout to do more than comment. All fields are optional — omitting the file entirely is safe (comment-only mode). A ready-to-copy template is at [`.github/dependency-scout.yml.example`](.github/dependency-scout.yml.example).

See [docs/configuration.md](docs/configuration.md) for the full field reference.

---

## What data leaves your machine

| Data | Where it goes | Notes |
|---|---|---|
| Package name, version numbers | OSV, Socket.dev, deps.dev, pypistats | Public registry APIs — this data is already public |
| Package archive (the actual .whl/.tgz/.gem) | Downloaded to local temp dir, deleted after diff | Never forwarded to any external service |
| Diff summary (changed file names + added/removed lines) | Your configured LLM (Claude/OpenAI/Ollama) | Up to 100 KB of actual code changes |
| Package description, release notes, Socket alert strings | Your configured LLM | Labeled as untrusted in the prompt |
| Source repo URL (from registry metadata) | GitHub API | Used to look up release tags and CI workflow changes |

**The diff summary does include real code lines** from the package archive. For private packages on a self-hosted registry, use Ollama to keep analysis fully local. The rule-based classifier (the default when no LLM key is configured) runs entirely locally.

---

## Ecosystem coverage

pip, npm, RubyGems, Cargo, Composer, Maven, NuGet, Go modules. Signal availability varies by registry — see [docs/architecture.md](docs/architecture.md) for the full coverage table.

---

## Learn more

- [Configuration reference](docs/configuration.md) — every `.github/dependency-scout.yml` field
- [How it works](docs/architecture.md) — two-workflow design, checks, classifier, security hardening
- [Deployment](docs/deployment.md) — production setup, secrets, Temporal options, scaling
- [Contributing](docs/contributing.md) — adding checks, ecosystems, detection patterns, design principles
- [Extending with plugins](docs/extending.md) — ecosystem, classifier, platform, and check plugins

---

*A [Temporal Community](https://temporal.io/community) project. Credit to [Daniel Hensby](https://github.com/dhensby) for inspiration.*
