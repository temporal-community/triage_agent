# Dependabot Supply Chain Scout

You have 47 unreviewed Dependabot PRs. You're going to merge most of them anyway. So did the maintainers of [XZ Utils](https://en.wikipedia.org/wiki/XZ_Utils_backdoor), [event-stream](https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident), and dozens of other projects before a malicious update slipped through.

**This bot gives every dependency PR a real second opinion before it merges.**

**TL;DR — what it checks and why:**
- **Does this version have known vulnerabilities?** Queries [OSV.dev](https://osv.dev) (includes the OpenSSF malicious-packages database) for CVEs and confirmed malicious packages.
- **Is the package itself suspicious?** [Socket.dev](https://socket.dev) scans for obfuscated code, install-time scripts, typosquatting, and permission creep.
- **What code actually changed?** Downloads and diffs both package archives — flags new binary `.so`/`.dll`/`.node` files (which execute on import), new install hooks, and unusual dependency additions.
- **Is the release fresh?** Very new releases (<24h) haven't had time for community review; older is safer.
- **Did the maintainer change?** A new account publishing a popular package is a classic supply chain attack vector.
- **Was it built from the right place?** Checks [SLSA/Sigstore](https://slsa.dev) attestations — cryptographic proof that the artifact was built by a specific CI pipeline from a specific repo. A mismatch is an automatic red flag.
- **Is the upstream repo healthy?** Queries the [OpenSSF Scorecard](https://securityscorecards.dev) to check if the project has dangerous CI workflows, overprivileged tokens, or no active maintenance.
- **Is this a zombie package?** Flags bumps to deprecated packages or patches to old major version lines while a newer major is actively maintained.
- **Is the PR itself suspicious?** Checks that only dependency files changed — finding a Dockerfile or CI workflow script in a "routine dep bump" is a red flag.

It classifies the risk as GREEN / YELLOW / RED, posts a comment explaining its reasoning, and takes action based on how you've configured it (or nothing if you haven't).

> **Status:** Experimental — works locally and with personal GitHub App installs. Supports pip, npm, and RubyGems. Public deployment coming soon.

---

## What it actually does

When a Dependabot or Renovate PR opens, the Scout:

1. **Fetches signals** from public APIs (PyPI/npm/RubyGems, OSV, Socket.dev, pypistats, SLSA provenance) — no API keys required for most signals
2. **Downloads and diffs** the package archive to see what code actually changed
3. **Classifies risk** as GREEN, YELLOW, or RED using Claude (or a rule-based fallback if you don't have an API key)
4. **Posts a verdict comment** to the PR explaining its reasoning
5. **Takes action** based on how you've configured it — or does nothing if you haven't

**RED** means something looks wrong: a new binary `.so`/`.node` file, obfuscated code, a maintainer account that appeared last week, exec/eval on dynamic strings, network calls added to install scripts.

**YELLOW** means "worth a look": major version bump, package released less than 7 days ago, new maintainer, unusually large diff for a patch bump, low download count.

**GREEN** means: patch or minor bump, well-established package, no CVEs, no red flags in the diff, release has been out for at least a week.

### Safe by default

**If you don't configure anything, the Scout only posts comments.** It never merges, closes, or requests review unless you explicitly enable it in `.github/triage-agent.yml`. This means installing it on a repo you haven't thought about yet is harmless.

### What the comment looks like

Every PR gets a comment like this:

---

> **Dependabot Triage Agent — 🟡 YELLOW**
>
> **Confidence:** 75%
>
> > Routine minor bump, but released 18 hours ago — too fresh to auto-merge by default. No CVEs, maintainer stable, diff looks like a docs update.
>
> **Flags:**
> - very fresh release (18h old)
>
> [View workflow run](http://localhost:8233/...) · [Configure triage behavior](.github/triage-agent.yml)

---

For a GREEN verdict, the comment is shorter — just the badge, reasoning, and a link. For RED, all flags are listed in full.

---

## Try it in 5 minutes

You need Python 3.10+, [`uv`](https://docs.astral.sh/uv/), and the [Temporal CLI](https://docs.temporal.io/cli).

```bash
git clone https://github.com/temporal-community/dependabot-supply-chain-scout
cd dependabot-supply-chain-scout
uv run python setup.py
```

The setup script checks prerequisites, walks you through GitHub credentials (PAT for local testing, GitHub App for production), writes `.env`, and prints the repo config snippet to paste into your target repo.

Then:

```bash
# Terminal 1 — Temporal dev server
temporal server start-dev

# Terminal 2 — worker
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

### Add keys to unlock more

| Keys configured | What changes |
|---|---|
| _(none)_ | Rule-based classifier, log-only output |
| `ANTHROPIC_API_KEY` | Claude classifies instead of rule-based thresholds |
| + `GITHUB_TOKEN` or GitHub App | Posts real PR comments |
| + `ENABLE_PR_ACTIONS=true` | Can auto-merge green PRs if you've configured it |
| + `SOCKET_API_KEY` | Adds Socket.dev supply chain score to signals |

Copy `.env.example` to `.env` and fill in what you have.

---

## Configuring your repo

Add `.github/triage-agent.yml` to any repo where you want the Scout to do more than comment:

```yaml
# .github/triage-agent.yml
auto_merge_enabled: true
auto_merge_classifications: [green]   # auto-merge green verdicts
reviewers: [alice, bob]               # request review on yellow
min_release_age_hours: 168            # never merge anything < 7 days old
block_classifications: [red]          # add a label + block merge on red
max_new_dependencies: 5               # flag as yellow if > 5 new direct deps added
```

All fields are optional. Any field you omit stays at its safe default (no auto-merge, no review requests, no blocking).

---

## Roadmap

- [x] PyPI, npm, and RubyGems ecosystem support
- [x] Seven parallel signal sources (metadata, OSV, Socket.dev, diff, release age, maintainer history, SLSA/Sigstore attestations)
- [x] LLM classifier with rule-based fallback
- [x] GitHub App auth
- [x] FastAPI webhook receiver
- [x] Per-repo config via `.github/triage-agent.yml`
- [x] Observe-only safe default
- [x] Replay test fixtures (workflow determinism guarantee)
- [x] EcosystemProvider plugin architecture (adding an ecosystem = one new file)
- [ ] Public GitHub App registration
- [ ] Composer (PHP), Maven (Java), and other ecosystems
- [ ] Renovate-triggered webhook support (currently Dependabot-focused)

---

## How it works under the hood

See [ARCHITECTURE.md](ARCHITECTURE.md) for the two-workflow Temporal design, signal sources, LLM classifier, security hardening, and how to run it against live GitHub webhooks.

---

*A [Temporal Community](https://temporal.io/community) project.*
