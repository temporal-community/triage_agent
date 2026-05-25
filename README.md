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

When a Dependabot or Renovate PR opens on **GitHub or GitLab**, the Scout:

1. **Fetches signals** from public APIs (PyPI/npm/RubyGems, OSV, Socket.dev, pypistats, SLSA provenance) — no API keys required for most signals
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
| `SOCKET_API_KEY` | Adds Socket.dev supply-chain score to signals |

Copy `.env.example` to `.env` and fill in what you have, or run `uv run python setup.py` to be walked through it interactively.

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
| `extra_signal_activities` | `[]` | Additional Temporal activity names to call (for ecosystem plugins) |

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

## Extending the Scout

Everything that varies between deployments is pluggable via Python entry points — no forking required.

| What to extend | Entry point group | How |
|---|---|---|
| New package ecosystem | `dependency_scout.ecosystems` | Implement `EcosystemProvider`, or use `RemoteEcosystemProvider` for non-Python stacks |
| Custom classifier (OpenAI, Gemini, …) | `dependency_scout.classifiers` | Implement `async def classify(signals) -> Verdict`, set `CLASSIFIER=name` |
| Extra signal activities | `dependency_scout.activities` | Decorate with `@activity.defn`, list in `extra_signal_activities` config |
| New dependency bot (PyUp, etc.) | call `register_bot_parser()` | Implement `BotParser` with `bot_logins` and `parse()` |

See [CONTRIBUTING.md](CONTRIBUTING.md) for full examples of each.

---

## Roadmap

- [x] pip, npm, RubyGems, Maven (Java/JVM), Composer (PHP), NuGet (.NET), Cargo (Rust), Go Modules
- [x] Eleven parallel signal sources (OSV, Socket.dev, diff, release age, maintainer, SLSA/Sigstore, OpenSSF Scorecard, deps.dev deprecation, version staleness, PR file audit, metadata)
- [x] LLM classifier with rule-based fallback
- [x] GitHub and GitLab support
- [x] FastAPI webhook receiver
- [x] Per-repo config via `.github/dependency-scout.yml`
- [x] Observe-only safe default (comment-only with no config file)
- [x] Replay test fixtures (workflow determinism guarantee)
- [x] Ecosystem plugin architecture — entry points + `RemoteEcosystemProvider` HTTP bridge for non-Python stacks
- [x] Pluggable classifier — Claude, OpenAI, Ollama, or any `dependency_scout.classifiers` plugin
- [x] Signal activity plugin architecture — third-party signals via `dependency_scout.activities` entry points, surfaced to LLM automatically
- [x] Temporal Cloud support — TLS credentials in `.env`, no code changes needed vs local dev
- [x] Renovate full support — title variants with/without `dependency` keyword, arrow and from/to body extraction, pre-release versions, false-positive prevention

---

## How it works under the hood

See [ARCHITECTURE.md](ARCHITECTURE.md) for the two-workflow Temporal design, signal sources, LLM classifier, security hardening, and how to run it against live GitHub webhooks.

For production deployment — secrets management, Temporal server options, reverse proxy, health monitoring — see [DEPLOYMENT.md](DEPLOYMENT.md).

For contributor docs — adding ecosystems, signals, classifiers, or custom plugins — see [CONTRIBUTING.md](CONTRIBUTING.md).

---

*A [Temporal Community](https://temporal.io/community) project. Credit to [Daniel Hensby](https://github.com/dhensby) for inspiration.*
