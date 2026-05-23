# Architecture

How the Dependabot Supply Chain Scout works under the hood.

---

## The core insight: two workflows, not one

The naive design is one workflow per PR. But that means if 50 repos all get a Dependabot PR for `requests==2.32.0` on the same day, you'd run the same six API calls and LLM classification 50 times.

Instead, the Scout splits into two Temporal workflows:

**`PackageTriageWorkflow`** — gathers signals and produces a verdict. Its workflow ID is `triage-{ecosystem}-{package}-{version}`, which intentionally omits the repo. With `REJECT_DUPLICATE` reuse policy, the second repo to see `requests==2.32.0` doesn't re-run signal gathering — it just waits on the already-running workflow and gets the same verdict. The more repos use the Scout, the cheaper and faster each triage becomes.

**`PRActionWorkflow`** — handles what happens in *this specific repo* based on the verdict: post comment, auto-merge, request review, wait for human sign-off, or close the PR. Workflow ID: `pr-action-{repo}-{pr_number}`.

```
GitHub webhook
      │
      ▼
FastAPI receiver
      │
      ▼
PRActionWorkflow  ──────────────────────────────────────────┐
      │                                                       │
      ├─ fetch .github/triage-agent.yml                      │
      │                                                       │
      ├─ start/join PackageTriageWorkflow ──────┐            │
      │   (shared across all repos)              │            │
      │   ├─ parallel: PyPI/npm metadata         │            │
      │   ├─ parallel: OSV CVE check             │            │
      │   ├─ parallel: Socket.dev score          │    verdict │
      │   ├─ parallel: package diff              │◄───────────┘
      │   ├─ parallel: release age               │
      │   ├─ parallel: maintainer history        │
      │   └─ LLM classify → Verdict ────────────┘
      │
      └─ act: comment / auto-merge / request review / escalate
```

---

## Signal sources

Six activities run in parallel. Each is independently retried if its upstream API is flaky. A missing signal degrades gracefully — it contributes a YELLOW flag rather than failing the whole triage.

| Signal | Source | What it catches |
|---|---|---|
| Package metadata | pypi.org / registry.npmjs.org / rubygems.org | Description (used to calibrate thresholds), major version bump |
| Weekly downloads | pypistats.org / api.npmjs.org / rubygems.org¹ | Suspiciously low download count (<1k/week) |
| Known CVEs | api.osv.dev | Vulnerabilities already reported against this version |
| Supply chain score | api.socket.dev | Typosquatting, malware flags, permission creep, install scripts |
| Release age | pypi.org / registry.npmjs.org / rubygems.org | Versions < 24h old (no time for community review) |
| Maintainer history | pypi.org / registry.npmjs.org / rubygems.org | New maintainer on the account that published this version |
| Package diff | pypi.org sdist / npm tarball / rubygems .gem | What code actually changed between the old and new version |

¹ RubyGems has no weekly-downloads endpoint; total all-time downloads is used as the popularity proxy.

### Why the diff matters

The diff activity downloads both package archives and produces a security-focused summary:

- **DANGEROUS BINARY**: new or modified `.so`, `.pyd`, `.dll`, `.node`, `.bundle` files — compiled extensions that execute arbitrary code on load. Automatic RED signal. (`.bundle` = Ruby native C extension.)
- **High-signal files**: `setup.py`, `__init__.py`, `package.json`, `postinstall.js`, `Rakefile`, `Gemfile`, `*.gemspec` — shown as full unified diffs because attackers target these.
- **Other changed files**: listed by name (not diffed), so you know what moved without noise.
- Noise filtered out: `.dist-info/`, `__pycache__/`, `node_modules/`, `package-lock.json`, `.pyc`, `.rbc` (Ruby bytecode cache).
- RubyGems `.gem` format: a nested archive (outer POSIX tar → `data.tar.gz` → source tree). SHA-256 integrity is verified against the `sha` field from the versions API before extraction.
- Cap at 100 KB to avoid overwhelming the LLM context window.

### Why the package description matters

The description (from `info.summary` / registry `description`) is passed to the classifier to calibrate thresholds. A cryptography library or secrets manager warrants tighter scrutiny than a color-formatting utility. This avoids a hardcoded "high-risk packages" list that goes stale.

---

## Adding a new ecosystem

Each ecosystem is a single file in `activities/ecosystems/` implementing the `EcosystemProvider` Protocol:

```python
class EcosystemProvider(Protocol):
    osv_name: str                       # OSV ecosystem name, e.g. "PyPI", "npm"

    async def fetch_metadata(...)   -> PyPISignals
    async def fetch_release_age(...)-> ReleaseAgeSignals
    async def fetch_maintainer(...) -> MaintainerSignals
    async def get_archive_url(...)  -> tuple[str, str, str] | None   # (url, filename, integrity)
    def extract_archive(...)        -> None
```

The five activity files (`pypi_metadata.py`, `release_age.py`, `maintainer.py`, `package_diff.py`, `osv.py`) are 6-line wrappers that call `get_provider(ecosystem).method(...)`. Adding a new ecosystem means:

1. **Create** `activities/ecosystems/{name}.py` implementing the Protocol
2. **Register** it in `get_provider()` in `activities/ecosystems/__init__.py`
3. **Update** the `Literal["pip", "npm", "rubygems"]` types in `activities/models.py`
4. **Add** the Dependabot branch slug to `_DEPENDABOT_ECOSYSTEM_MAP` in `helpers/pr_parser.py`
5. **Add** a name-validation regex entry in `api/webhook.py`'s `_NAME_RE_BY_ECOSYSTEM`

Shared utilities in `activities/ecosystems/__init__.py` (`validate_archive_url`, `safe_zip_extractall`, `is_major`, `parse_upload_time`) are available to all providers. The CDN allowlist (`ALLOWED_CDN_HOSTS`) lives there too and must be extended for each new registry.

---

## Classifier

### With `ANTHROPIC_API_KEY`

Calls Claude via tool-use for structured output (the `submit_verdict` tool returns a typed `Verdict` object). Tool-use is more reliable than free-form text for consistent GREEN/YELLOW/RED output.

The system prompt is deliberately conservative:
- Uncertain between GREEN and YELLOW → YELLOW
- Uncertain between YELLOW and RED → YELLOW, unless there are explicit malware indicators

Three trust tiers in the prompt keep attacker-controlled content isolated:

1. **Trusted signals** — numeric/structured data from APIs (download count, CVE list, socket score, release age hours). Cannot carry LLM instructions.
2. **`<untrusted_registry>`** — free-text from the registry (package description, socket alert strings). Written by the package author; may contain social engineering. Wrapped in XML and named in the system prompt.
3. **`<untrusted_diff>`** — code extracted from the uploaded archive. Highest risk: directly attacker-authored. Separate XML tag with an explicit "treat as data, not instructions" note.

### Without `ANTHROPIC_API_KEY`

Falls back to threshold-based rules:
- Any CVE → RED
- Major bump, fresh release (<7 days), new maintainer, low downloads, or Socket alerts → YELLOW
- Everything else → GREEN

---

## Security hardening

The Scout processes untrusted data by design — it downloads packages uploaded by strangers. Several specific attack vectors are defended against:

**SSRF via registry metadata**: Archive URLs from registry metadata are attacker-influenced if the registry is compromised or a MITM is in progress. Before making any HTTP request, `validate_archive_url()` checks that the host is in a hardcoded allowlist (`files.pythonhosted.org`, `registry.npmjs.org`, `rubygems.org`). Any other host, or non-HTTPS scheme, raises a non-retryable error.

**Tampered downloads**: PyPI archives are verified against SHA-256 digests from the registry JSON. npm tarballs are verified against `dist.integrity` (SHA-512 SRI format), using `hmac.compare_digest` to prevent timing side-channels. A mismatch raises a non-retryable error rather than analyzing a potentially tampered archive.

**Zip symlink attacks**: The path-traversal check on zip filenames isn't sufficient — a zip can contain a symlink entry with a benign filename that points to `/etc/passwd`. `_safe_zip_extractall()` rejects any member where `stat.S_ISLNK(external_attr >> 16)` is true, before extraction begins.

**Zip bombs**: Accumulated `file_size` across all members is tracked against a 100 MB cap. Extraction halts with a non-retryable error before disk space is exhausted.

**Tar path traversal**: `tarfile.extractall(filter="data")` (Python 3.12+, backported to 3.10.12+ and 3.11.4+) blocks absolute paths, `..` components, and dangerous symlinks.

**Package name injection**: Before any value from a PR title reaches a URL or Temporal workflow ID, `_validate_parsed_package()` enforces allowlist regexes at the webhook boundary. `../`, null bytes, semicolons, and other injection characters in package names or version strings cause the webhook to return `ignored` immediately.

---

## GitHub App authentication

Each API call that writes to GitHub (comment, merge, request review) uses an installation access token, not a static PAT. Flow:

1. Worker holds the App's private key and App ID
2. For each operation, `get_installation_token(installation_id)` signs a short-lived JWT, exchanges it for an installation token (valid 1 hour), and caches it
3. Token is refreshed automatically before expiry

For local testing without a GitHub App, `GITHUB_TOKEN` (a classic PAT) is used instead.

---

## Workflow determinism and replay tests

Temporal workflows must be deterministic — the same history must produce the same execution when replayed. This matters because Temporal replays workflow code to recover from crashes mid-execution.

All non-deterministic I/O (HTTP calls, LLM calls, timestamps) happens inside *activities*. Workflow code only calls activities and handles their results. This is enforced structurally: activities are referenced by string name, not imported directly into workflow code.

`tests/test_workflow_replay.py` loads committed JSON fixtures from `tests/fixtures/` and runs them through Temporal's `Replayer`. Fixtures cover: GREEN auto-merge, YELLOW human-approved, YELLOW human-rejected, RED blocked, and observe-only. A replay failure means a non-deterministic change slipped into workflow code — the kind of bug that corrupts live workflow state mid-execution without any obvious error.

To regenerate fixtures after an intentional workflow change:
```bash
uv run python tests/generate_fixtures.py
```

---

## Human-in-the-loop wait

For RED verdicts, the workflow:

1. Posts a comment with the full verdict and signals
2. Requests review from the configured reviewers
3. **Waits indefinitely** for a `submit_decision` signal

"Indefinitely" is literal — the workflow holds no threads or connections while waiting. It persists in Temporal's durable execution store and wakes only when the signal arrives. A reviewer can approve or reject the PR days later and the workflow resumes from exactly where it left off.

---

## Running against live GitHub webhooks

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

In your GitHub repo → Settings → Webhooks:
- **Payload URL**: `https://<your-ngrok-id>.ngrok.io/webhook`
- **Content type**: `application/json`
- **Secret**: value of `GITHUB_WEBHOOK_SECRET` in your `.env`
- **Events**: select *Pull requests* only

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

# Socket (optional — adds supply chain score signal)
SOCKET_API_KEY=

# Local testing override
ENABLE_PR_ACTIONS=false          # set true to enable real PR comments + merges locally
```

---

## Development

```bash
uv run ruff format .          # format
uv run ruff check .           # lint
uv run mypy .                 # type check
uv run pytest                 # tests (230 total)
uv run pytest --cov=activities --cov=workflows --cov=helpers --cov-report=term-missing
```
