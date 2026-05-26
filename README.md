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

Classifies 🟢 GREEN / 🟡 YELLOW / 🔴 RED, posts a comment explaining its reasoning, and takes action based on your config (or nothing if you haven't configured anything).

> **Status:** Experimental — self-hosted, bring your own keys. No shared infrastructure, no accounts, no sign-up.

<img width="891" height="596" alt="Testing 24 PRs at once, with LLM-based classifier determining both security checks and merge-ability" src="https://github.com/user-attachments/assets/e3246410-b45b-405c-8edc-4f2e505689f3" />

<img width="678" height="685" alt="Sample comment showing checks" src="https://github.com/user-attachments/assets/cba5dcac-713e-4bde-a31e-0410ff79aefa" />

---

## Quick start

You need Python 3.10+, [`uv`](https://docs.astral.sh/uv/), and the [Temporal CLI](https://docs.temporal.io/cli).

```bash
git clone https://github.com/temporal-community/dependency-scout
cd dependency-scout
uv run python setup.py
```

The setup script checks prerequisites, explains the tradeoffs between a PAT and a GitHub App, lets you choose your LLM (Claude, OpenAI, Ollama, or skip), and writes `.env`.

The Temporal dev server runs entirely on your machine — no account, no payment, no sign-up:

```bash
# Terminal 1 — Temporal dev server
temporal server start-dev

# Terminal 2 — Scout worker
uv run python -m worker

# Terminal 3 — triage a single PR
uv run python -m triage https://github.com/your-org/your-repo/pull/123
```

Open **http://localhost:8233** to watch the workflow run. With `GITHUB_TOKEN` set, the Scout posts a comment directly on the PR — [here's a real example](https://github.com/temporalio/ai-cookbook/pull/104#issuecomment-4543267396).

No API keys needed to start — the rule-based classifier runs entirely locally. Without `GITHUB_TOKEN` it prints what it would have posted instead of actually posting it.

### Batch-triage your open PRs

Once the worker is running, point it at a whole repo to clear the backlog:

```bash
# Triage every open Dependabot/Renovate PR in a repo
uv run python -m triage --repo your-org/your-repo

# Or limit to a subset while you're getting a feel for it
uv run python -m triage --repo your-org/your-repo --limit 5
```

### Configure your stack

The Scout works with zero configuration — rule-based classifier, no PR comments, no auto-actions. Each addition makes it smarter or more capable:

| `.env` setting | What it enables |
|---|---|
| _(none)_ | Rule-based classifier, log-only output |
| `ANTHROPIC_API_KEY` | Claude classifies (set `ANTHROPIC_MODEL` to pin a version) |
| `OPENAI_API_KEY` + `OPENAI_MODEL` | OpenAI classifies instead |
| `OLLAMA_HOST` + `OLLAMA_MODEL` | Local Ollama classifies — free, no data leaves your machine |
| `CLASSIFIER=rule_based` | Force rule-based even when an LLM key is present |
| `GITHUB_TOKEN` or GitHub App | Posts real PR comments on GitHub |
| `GITLAB_TOKEN` | Posts real MR comments on GitLab |
| `ENABLE_PR_ACTIONS=true` | Can automatically merge GREEN PRs and/or close RED ones |
| `SOCKET_API_KEY` | Adds Socket.dev supply-chain score check ([create token](https://socket.dev/dashboard/settings/api-tokens) — scope: `packages:list`) |

Copy `.env.example` to `.env` and fill in what you have, or run `uv run python setup.py` to be walked through it interactively.

### What's next: continuous triage on every new PR

Once you're happy with the results, you can set up the Scout as a persistent webhook listener — it triages every new Dependabot or Renovate PR automatically and can auto-merge GREEN ones or close RED ones. This requires a server that stays up when your laptop closes. See [docs/deployment.md](docs/deployment.md).

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

pip/uv, npm, RubyGems, Cargo, Composer, Maven/Gradle, NuGet, Go modules, GitHub Actions, Mix (Hex), Pub (Dart/Flutter), Elm, Docker, Terraform, Swift. Signal availability varies by registry — see [docs/architecture.md](docs/architecture.md) for the full coverage table.

---

## Learn more

- [Configuration reference](docs/configuration.md) — every `.github/dependency-scout.yml` field
- [How it works](docs/architecture.md) — two-workflow design, checks, classifier, security hardening
- [Deployment](docs/deployment.md) — production setup, secrets, Temporal options, scaling
- [Security hardening](docs/security.md) — token scoping, auto-merge thresholds, prompt injection
- [Contributing](docs/contributing.md) — adding checks, ecosystems, detection patterns, design principles
- [Extending with plugins](docs/extending.md) — ecosystem, classifier, platform, and check plugins

---

*A [Temporal Community](https://temporal.io/community) project. Credit to [Daniel Hensby](https://github.com/dhensby) for inspiration.*
