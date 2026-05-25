# Dependency Scout

You have 47 unreviewed Dependabot PRs. You're going to merge most of them anyway. So did the maintainers of [XZ Utils](https://en.wikipedia.org/wiki/XZ_Utils_backdoor), [event-stream](https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident), and dozens of other projects before a malicious update slipped through.

**This bot gives every dependency PR a real second opinion before it merges.**

**TL;DR — what it checks and why:**
- **Does this version have known vulnerabilities?** Queries [OSV - Open Source Vulnerabilities database](https://osv.dev) (includes the [OpenSSF malicious-packages database](https://github.com/ossf/malicious-packages)) for CVEs and confirmed malicious packages.
- **Is the package itself suspicious?** [Socket.dev](https://socket.dev) scans for obfuscated code, install-time scripts, typosquatting, and permission creep.
- **What code actually changed?** Downloads and diffs both package archives — flags new binary `.so`/`.dll`/`.node` files (which execute on import), new or modified install hooks, network calls added to library code, new dependencies sourced from git URLs instead of the registry (bypasses registry malware scanning), obfuscated code patterns, and unusual dependency additions.
- **Is the release too fresh?** Releases younger than 24h are flagged as "very fresh"; younger than 7 days as "recent". The Scout won't automatically merge anything under 7 days old by default.
- **Did the maintainer change?** A new account publishing a popular package is a classic supply chain attack vector.
- **Was it built from the right place?** Checks [SLSA](https://slsa.dev) (Supply-chain Levels for Software Artifacts) attestations — cryptographic proof, signed by the CI system, that the package was built from a specific repo and commit. Also flags dropped tag signing and releases drafted significantly before publishing (a re-release pattern). A mismatch is an automatic red flag.
- **Is the upstream repo healthy?** Queries the [OpenSSF Scorecard](https://securityscorecards.dev) to check if the project has dangerous CI workflows, overprivileged tokens, or no active maintenance.
- **Is this a zombie package?** Flags bumps to deprecated packages or patches to old major version lines while a newer major is actively maintained.
- **Is the PR itself suspicious?** Checks that only dependency files changed — finding a Dockerfile or CI workflow script in a "routine dep bump" is a red flag.

It classifies the risk as GREEN / YELLOW / RED, posts a comment explaining its reasoning, and takes action based on how you've configured it (or nothing if you haven't).

> **Status:** Experimental — self-hosted, bring your own keys. Run it locally or deploy it to your own server (see [DEPLOYMENT.md](DEPLOYMENT.md)). No shared infrastructure, no accounts, no sign-up.

---

## What it actually does

When a Dependabot (or [Renovate](https://github.com/renovatebot/renovate)) PR opens on GitHub (or GitLab), the Scout:

1. **Runs checks** from public APIs (PyPI/npm/RubyGems, OSV, Socket.dev, pypistats, SLSA provenance) — no API keys required for most checks
2. **Downloads and diffs** the package archive to see what code actually changed
3. **Classifies risk** as GREEN, YELLOW, or RED using your choice of LLM — Claude, OpenAI, Ollama, or a custom plugin — with a rule-based fallback if you'd rather not use any LLM
4. **Posts a verdict comment** to the PR/MR explaining its reasoning
5. **Takes action** based on how you've configured it — or does nothing if you haven't

**RED** means something looks wrong: a new binary `.so`/`.node` file, obfuscated code, a maintainer account that appeared last week, exec/eval on dynamic strings, network calls added to install scripts.

**YELLOW** means "worth a look": major version bump, package released less than 7 days ago, new maintainer, unusually large diff for a patch bump, low download count.

**GREEN** means: patch or minor bump, well-established package, no CVEs, no red flags in the diff, release has been out for at least a week.

### Safe by default

**If you don't configure anything, the Scout only posts comments.** It never merges, closes, or requests review unless you explicitly enable it in `.github/dependency-scout.yml`. This means installing it on a repo you haven't thought about yet is harmless.

### What the comment looks like

Every PR gets a comment like this:

---

> **Dependabot Triage Agent — 🟡 YELLOW**
>
> **Confidence:** 75%
>
> > Routine minor bump, but released 18 hours ago — too fresh to merge automatically by default. No CVEs, maintainer stable, diff looks like a docs update.
>
> **Flags:**
> - very fresh release (18h old)
>
> [View workflow run](http://localhost:8233/...) · [Configure triage behavior](.github/dependency-scout.yml)

---

For a GREEN verdict, the comment is shorter — just the badge, reasoning, and a link. For RED, all flags are listed in full.

---

## Try it in 5 minutes

You need Python 3.10+, [`uv`](https://docs.astral.sh/uv/), and the [Temporal CLI](https://docs.temporal.io/cli).

```bash
git clone https://github.com/temporal-community/dependency-scout
cd dependency-scout
uv run python setup.py
```

The setup script checks prerequisites, explains the tradeoffs between a PAT and a GitHub App, lets you choose your LLM (Claude, OpenAI, Ollama, or skip), writes `.env`, and prints the repo config snippet to paste into your target repo.

Then:

```bash
# Terminal 1 — Temporal dev server (the job queue and state store)
# Skip this if you're using Temporal Cloud — set TEMPORAL_TLS_CERT/KEY in .env instead
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
| `ENABLE_PR_ACTIONS=true` | Can automatically merge GREEN PRs and/or close RED ones, based on your config |
| `SOCKET_API_KEY` | Adds Socket.dev supply-chain score check |

Copy `.env.example` to `.env` and fill in what you have, or run `uv run python setup.py` to be walked through it interactively.

### From local test to live PRs

The test above fires a one-off triage against a public package. To get the Scout commenting on your actual Dependabot/Renovate PRs, you need two more things:

**1. A running worker** — the `uv run python -m worker` process from above, but somewhere that stays up. The cheapest options:

- A small VPS (the worker idles at ~50 MB RAM between triages)
- A free-tier fly.io or Railway app using the included `Dockerfile`
- Temporal Cloud (free tier) + any serverless function for the worker — see [DEPLOYMENT.md](DEPLOYMENT.md)

**2. A webhook pointing at the worker** — GitHub/GitLab needs to call your FastAPI server when a PR opens:

```bash
# Start the webhook receiver (port 8000 by default)
uv run uvicorn api.webhook:app --host 0.0.0.0 --port 8000

# Expose it if developing locally (ngrok, cloudflare tunnel, etc.)
ngrok http 8000
```

Then in your GitHub repo: Settings → Webhooks → Add webhook:
- Payload URL: `https://your-host/webhook/github`
- Content type: `application/json`
- Secret: same value as `GITHUB_WEBHOOK_SECRET` in your `.env`
- Events: **Pull requests** only

Full production setup (TLS, process manager, Temporal Cloud option) is in [DEPLOYMENT.md](DEPLOYMENT.md).

### Why does this need Temporal at all?

Fair question. You could imagine this as a GitHub Action — trigger on PR open, run checks, post a comment. The problem is reliability and deduplication:

- **Reliability**: If your server restarts mid-triage, a GitHub Action just fails silently. Temporal automatically retries failed steps and resumes exactly where it left off — even if the process crashes and restarts.
- **Deduplication**: If 30 repos all open Dependabot PRs for `requests==2.32.0` on the same day, a naive implementation downloads the same 2 MB archive and runs the same API calls 30 times. Temporal lets the second through thirtieth repo attach to the already-running triage and get the same result for free.
- **Long waits**: Waiting for a human to approve a YELLOW verdict might take days. A Temporal workflow can pause and resume when the approval arrives — no polling, no timeouts.

In practice, for a single-repo installation with light PR volume, Temporal is invisible infrastructure. The `temporal server start-dev` command in the quickstart above is all you ever need to interact with it. For production, [Temporal Cloud](https://temporal.io/cloud) has a free tier and removes the need to run the Temporal server yourself at all.

---

## Configuring your repo

Add `.github/dependency-scout.yml` to any repo where you want the Scout to do more than comment. All fields are optional — omitting the file entirely is safe (comment-only mode).

A ready-to-copy template is at [`.github/dependency-scout.yml.example`](.github/dependency-scout.yml.example).

### Full config reference

| Field | Default | What it does |
|---|---|---|
| `auto_merge_enabled` | `false` | Enable auto-merge for classified PRs |
| `auto_merge_classifications` | `["green"]` | Which verdicts are eligible for auto-merge |
| `auto_merge_min_confidence` | `0.80` | Classifier confidence required before auto-merge fires (0–1) |
| `min_release_age_hours` | `168` (7 days) | Never auto-merge a release newer than this, even if GREEN |
| `reviewers` | `[]` | GitHub usernames to request review on YELLOW verdicts |
| `block_classifications` | `["red"]` | Close the PR and add a label for these verdicts |
| `max_new_dependencies` | `5` | Flag as YELLOW when a bump adds more than this many new direct deps |
| `extra_check_activities` | `[]` | Additional Temporal activity names to call (for ecosystem plugins) |

**Minimal "just auto-merge safe stuff" config:**

```yaml
# .github/dependency-scout.yml
auto_merge_enabled: true
reviewers: [your-github-username]   # gets pinged on yellow
```

**Stricter config — wait a week, block red, request two reviewers on yellow:**

```yaml
auto_merge_enabled: true
auto_merge_min_confidence: 0.90
min_release_age_hours: 168
reviewers: [alice, bob]
block_classifications: [red]
```

**Observe-only (just get comments, never take action):**

```yaml
# Empty file, or omit the file entirely — this is the default.
block_classifications: []   # override the default red-blocking if you want truly zero action
```

---

## Ecosystem coverage

The Scout ships with eight ecosystems. Signal availability varies by what the registry exposes:

| Ecosystem | Registry | Download stats | Maintainer change | SLSA attestation | Archive diff |
|---|---|---|---|---|---|
| pip (Python) | PyPI | ✅ weekly (pypistats) | ✅ | ✅ Sigstore | ✅ |
| npm (Node.js) | npmjs.com | ✅ weekly | ✅ | ✅ Sigstore | ✅ |
| RubyGems | rubygems.org | ✅ daily avg | ✅ | — | ✅ |
| Cargo (Rust) | crates.io | ✅ 90-day | ✅ per-version publisher | — | ✅ |
| Composer (PHP) | Packagist | ✅ monthly avg | — | — | ✅ |
| Maven (Java/JVM) | Maven Central | — | ✅ | — | ✅ |
| NuGet (.NET) | nuget.org | — | — | — | ✅ |
| Go modules | proxy.golang.org | — | — | — | ✅ |

All ecosystems get: OSV vulnerability check, Socket.dev score (npm-focused but available), release age, GitHub release checks (tag signing, timing, CI changes), OpenSSF Scorecard, deps.dev deprecation, and version staleness detection. These signals don't depend on the registry — they work off the package's linked GitHub repo and public databases.

**My ecosystem isn't in this list.** Adding it is about 150 lines in one Python file — see [CONTRIBUTING.md](CONTRIBUTING.md). If your ecosystem logic lives in a non-Python stack (PHP, Go, Ruby, Java…), the `RemoteEcosystemProvider` bridge lets you write a small HTTP service in your language and register it as a plugin — no Python expertise required. The bridge handles all the Temporal integration; your service just responds to POST requests with JSON.

---

## What data leaves your machine

| Data | Where it goes | Notes |
|---|---|---|
| Package name, version numbers | OSV, Socket.dev, deps.dev, pypistats | Public registry APIs — this data is already public |
| Package archive (the actual .whl/.tgz/.gem) | Downloaded to local temp dir, deleted after diff | Never forwarded to any external service |
| Diff summary (changed file names + added/removed lines) | Your configured LLM (Claude/OpenAI/Ollama) | Up to 100 KB of actual code changes; see below |
| Package description, release notes, Socket alert strings | Your configured LLM | Labeled as untrusted in the prompt |
| Source repo URL (from registry metadata) | GitHub API | Used to look up release tags and CI workflow changes |

**The diff summary does include real code lines** from the package archive — the lines that changed between the old and new version. For published packages (PyPI, npm, etc.) this is already public. For private packages on a self-hosted registry, use Ollama to keep analysis fully local: `OLLAMA_HOST=http://localhost:11434` and `OLLAMA_MODEL=llama3.2` in your `.env` and nothing leaves your network.

The rule-based classifier (the default when no LLM key is configured) runs entirely locally — no data is sent to any external service beyond the check APIs listed above.

---

## Extending the Scout

Everything that varies between deployments is pluggable via Python entry points — no forking required.

| What to extend | Entry point group | How |
|---|---|---|
| New package ecosystem | `dependency_scout.ecosystems` | Implement `EcosystemProvider`, or use `RemoteEcosystemProvider` for non-Python stacks |
| Custom classifier (OpenAI, Gemini, …) | `dependency_scout.classifiers` | Implement `async def classify(checks) -> Verdict`, set `CLASSIFIER=name` |
| Extra check activities | `dependency_scout.activities` | Decorate with `@activity.defn`, list in `extra_check_activities` config |
| New dependency bot (PyUp, etc.) | call `register_bot_parser()` | Implement `BotParser` with `bot_logins` and `parse()` |

See [CONTRIBUTING.md](CONTRIBUTING.md) for full examples of each.

---

## Roadmap

- [x] pip, npm, RubyGems, Maven (Java/JVM), Composer (PHP), NuGet (.NET), Cargo (Rust), Go Modules
- [x] Eleven parallel check sources (OSV, Socket.dev, diff, release age, maintainer, SLSA/Sigstore, OpenSSF Scorecard, deps.dev deprecation, version staleness, PR file audit, metadata)
- [x] LLM classifier with rule-based fallback
- [x] GitHub and GitLab support
- [x] FastAPI webhook receiver
- [x] Per-repo config via `.github/dependency-scout.yml`
- [x] Observe-only safe default (comment-only with no config file)
- [x] Replay test fixtures (workflow determinism guarantee)
- [x] Ecosystem plugin architecture — entry points + `RemoteEcosystemProvider` HTTP bridge for non-Python stacks
- [x] Pluggable classifier — Claude, OpenAI, Ollama, or any `dependency_scout.classifiers` plugin
- [x] Check activity plugin architecture — third-party checks via `dependency_scout.activities` entry points, surfaced to LLM automatically
- [x] Temporal Cloud support — TLS credentials in `.env`, no code changes needed vs local dev
- [x] Renovate full support — title variants with/without `dependency` keyword, arrow and from/to body extraction, pre-release versions, false-positive prevention

---

## Project layout

```
activities/     Temporal activity definitions — one file per check source.
                Each activity fetches one kind of data (PyPI metadata, Socket score,
                OSV vulnerabilities, package diff, maintainer info, etc.) and returns
                a typed Pydantic model. Activities run in parallel inside the workflow.

ecosystems/     Per-ecosystem providers (pip, npm, RubyGems, Cargo, Go, Composer,
                Maven, NuGet). Each implements EcosystemProvider: how to fetch release
                metadata, download archives, extract them, and look up VCS repos.
                remote.py is the HTTP bridge for non-Python ecosystem plugins.

workflows/      Two Temporal workflow definitions.
                package_triage_workflow.py — orchestrates all check activities,
                collects results into PackageChecks, calls the classifier, returns
                a Verdict. pr_action_workflow.py — receives the Verdict and takes
                action (comment, merge, close, request review) via the platform client.

classifiers/    Classifier implementations — Claude (default), OpenAI, Ollama, and
                rule-based fallback. Selected by the CLASSIFIER env var or loaded via
                dependency_scout.classifiers entry points for custom plugins.

models/         Shared Pydantic data models: PRContext, RepoConfig, PackageChecks
                (and all its signal sub-models), and Verdict. Imported by activities,
                workflows, classifiers, and tests.

platforms/      GitHub and GitLab platform clients: post comments, merge/close PRs,
                request review, and check which files changed in a PR.

helpers/        Shared utilities: async HTTP client, activity result cache, GitHub App
                token refresh, comment formatter, repo config loader, bot-PR parsers
                (Dependabot/Renovate), and the LLM prompt templates.

api/            FastAPI webhook receiver. Parses incoming Dependabot and Renovate
                webhook payloads and starts a PackageTriageWorkflow via the Temporal
                client. Entry point for production traffic.

detections/     YAML files containing every regex pattern used for supply chain
                attack detection: network calls (160 patterns across 11 languages),
                obfuscation/gzip/zero-width tricks, OS persistence mechanisms,
                worm propagation signatures, and suspicious file type lists.
                Edit these to add coverage for new attacks — no Python required.
                detections/__init__.py loads all YAML at startup and exports
                typed constants that the rest of the code uses.

tests/          pytest test suite — one file per module, plus test_workflow_replay.py
                which replays recorded Temporal event histories from tests/fixtures/
                to catch non-deterministic workflow changes.
```

---

## How it works under the hood

See [ARCHITECTURE.md](ARCHITECTURE.md) for the two-workflow Temporal design, signal sources, LLM classifier, security hardening, and how to run it against live GitHub webhooks.

For production deployment — secrets management, Temporal server options, reverse proxy, health monitoring — see [DEPLOYMENT.md](DEPLOYMENT.md).

For contributor docs — adding ecosystems, signals, classifiers, or custom plugins — see [CONTRIBUTING.md](CONTRIBUTING.md).

---

*A [Temporal Community](https://temporal.io/community) project. Credit to [Daniel Hensby](https://github.com/dhensby) for inspiration.*
