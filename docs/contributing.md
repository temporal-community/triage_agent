# Contributing

How to contribute to the Dependency Scout codebase — adding checks, ecosystems, detection patterns, fixing bugs, or improving the classifier.

To build *on top of* the Scout without modifying this repo (custom ecosystems, classifiers, or check plugins), see [extending.md](extending.md) instead.

---

## Adding a detection pattern for a new attack

This is the lowest-barrier contribution: a two-line YAML edit, no Python required.

Detection patterns (regex strings that flag suspicious code in package diffs) live in `checks/signatures/`:

| File | What it covers |
|---|---|
| `net_calls.yaml` | Outbound network calls in library code, by language extension |
| `obfuscation.yaml` | Encoded payloads, zero-width Unicode tricks |
| `persistence.yaml` | OS persistence mechanisms, npm worm propagation |
| `file_types.yaml` | Suspicious filenames, dangerous binary extensions |

Add a pattern — for example, a new HTTP client library that a recent attack used:

```yaml
# checks/signatures/net_calls.yaml, under the .py block:
- pattern: 'evil_http\.fetch\b'
  desc: EvilHTTP library used in SupplyChainCorp May 2026 attack
```

Use **single-quoted** YAML strings for regex — backslashes work as-is without doubling.

Run `uv run pytest tests/test_signatures.py -v` to verify your pattern compiles. Then run the full suite (`uv run pytest -x -q`).

Use the `/add-detection` Claude Code skill for a guided walkthrough in Claude Code.

---

## Adding a new built-in ecosystem

The plugin architecture makes this straightforward. Adding a new ecosystem is approximately 150 lines in one file.

Also see [ecosystems/README.md](../ecosystems/README.md) for the coverage table and required-method reference.

**Step 1 — Create `ecosystems/{name}.py`**

Implement the `EcosystemProvider` Protocol. Copy an existing provider (e.g. `rubygems.py`) as a starting point. Set `ecosystem_name` to the canonical key — `get_provider()` discovers it automatically:

```python
from ecosystems import is_major, parse_upload_time, validate_archive_url
from models import AttestationChecks, MaintainerChecks, MetadataChecks, ReleaseAgeChecks

class ComposerProvider:
    ecosystem_name = "composer"  # auto-discovered by get_provider()
    osv_name = "Packagist"       # must match the ecosystem name used by api.osv.dev

    async def fetch_metadata(self, package, old_version, new_version) -> MetadataChecks: ...
    async def fetch_release_age(self, package, new_version) -> ReleaseAgeChecks: ...
    async def fetch_maintainer(self, package, old_version, new_version) -> MaintainerChecks: ...
    async def get_archive_url(self, client, package, version) -> tuple[str, str, str] | None: ...
    def extract_archive(self, archive_bytes, filename, dest) -> None: ...
    async def fetch_attestations(self, package, old_version, new_version) -> AttestationChecks: ...
    async def fetch_release(self, package, old_version, version) -> ReleaseChecks: ...
```

`get_archive_url` returns `(url, filename, integrity_string)`. Call `validate_archive_url(url)` before returning — this enforces the CDN allowlist. Add your registry's CDN host to `ALLOWED_CDN_HOSTS` in `ecosystems/__init__.py`.

**Step 2 — Update the type model**

In `models/__init__.py`, add the new ecosystem name to the `Literal[...]` types for ecosystem names.

**Step 3 — Wire up Dependabot branch parsing**

In `helpers/pr_parser.py`, add the `dependabot_slug` → `ecosystem_name` mapping to `_DEPENDABOT_ECOSYSTEM_MAP`.

**Step 4 — Add package name validation**

In `api/webhook.py`, add a `name_re` entry to `_NAME_RE_BY_ECOSYSTEM` (or rely on `get_name_re()` from `ecosystems/__init__.py` if the webhook already calls that).

**Step 5 — Write tests**

Add a test file under `tests/` following the existing patterns (e.g. `tests/test_pip_*.py` or `tests/test_npm_*.py`). Use `respx` for HTTP mocking and `ActivityEnvironment` for the activity harness. Each method needs at minimum: success case, 404/not-found case, and (for attestations) a no-attestation case. Aim to keep overall coverage above 95%.

**Step 6 — Regenerate replay fixtures (if needed)**

If you changed any workflow code (unlikely for a pure ecosystem add, but possible):

```bash
uv run python tests/generate_fixtures.py
```

---

## Adding a new built-in check

Each check is a parallel activity that gathers one category of supply chain data and returns a typed sub-model. All checks run at the same time; a failing check gets degraded defaults rather than crashing the workflow.

**Step 1 — Define the sub-model in `models/`**

```python
class MyNewChecks(BaseModel):
    some_flag: bool = False
    some_score: int | None = None
```

All fields need defaults so the model can be instantiated as a zero/degraded state when the activity fails. Then add it as a nested field in `PackageChecks`:

```python
class PackageChecks(BaseModel):
    ...
    my_new: MyNewChecks = Field(default_factory=MyNewChecks)
```

**Step 2 — Create `checks/my_new_check.py`**

```python
from temporalio import activity
from models import MyNewChecks

@activity.defn(name="activities.my_new_check.check")
async def check(ecosystem: str, package: str, old_version: str, new_version: str) -> MyNewChecks:
    try:
        # fetch data from an external API
        return MyNewChecks(some_flag=True, some_score=42)
    except Exception:
        return MyNewChecks()   # degraded defaults — never raise from a check activity
```

The activity name string is what the workflow references. It must match exactly.

**Caching** — add an `ActivityCache` to avoid redundant network calls when multiple repos bump the same package simultaneously:

```python
from helpers.cache import ActivityCache, INDEFINITE

# Pick a TTL that matches how often the data can legitimately change:
_cache = ActivityCache()                     # immutable (archive contents, provenance, upload timestamps)
_cache = ActivityCache(ttl_seconds=3600)     # can change, but rarely within an hour (CVEs, scores)
_cache = ActivityCache(ttl_seconds=86400)    # changes slowly (deprecation, repo health)

@activity.defn(name="activities.my_new_check.check")
async def check(ecosystem, package, old_version, new_version):
    key = (ecosystem, package, new_version)  # omit old_version if it doesn't affect the result
    if (hit := _cache.get(key)) is not None:
        activity.logger.debug("my_new_check cache hit: %s %s", package, new_version)
        return hit
    result = await _fetch(...)
    _cache.set(key, result)   # only cache successful results — don't cache degraded defaults
    return result
```

Tests are isolated automatically — a `conftest.py` fixture clears all caches before and after each test.

**Step 3 — Add to `_CHECK_REGISTRY` in `workflows/package_triage_workflow.py`**

**Append** a row to `_CHECK_REGISTRY` — do not insert mid-list, as this changes Temporal's command sequence and breaks replay of existing histories:

```python
_CHECK_REGISTRY: list[tuple[str, str, type, bool]] = [
    ...
    ("my_new", "activities.my_new_check.check", MyNewChecks, False),
    #           ^activity name string            ^result type  ^True = 2-min timeout
]
```

The first element (`"my_new"`) must match the field name you added to `PackageChecks`.

**Step 4 — Use the check in `classifiers/`**

Add logic to `_rule_based` using `signals.my_new.some_flag`, and/or let the LLM see it — it already appears in the trusted JSON block via `PackageChecks.model_dump()`. Forgetting this step will cause a test failure in `tests/test_check_wiring.py`.

**Step 5 — Regenerate replay fixtures**

Any change to the workflow's gather list changes its Temporal command sequence. Regenerate the determinism fixtures:

```bash
# Temporal must be running — the generator executes real workflows
temporal server start-dev   # in a separate terminal, if not already running

uv run python tests/generate_fixtures.py
```

The script prints one line per fixture as it runs. If it hangs, Temporal isn't reachable. Commit the updated files in `tests/fixtures/`.

---

## Running locally

```bash
uv sync
uv run ruff format .          # format
uv run ruff check .           # lint
uv run mypy .                 # type check
uv run pytest                 # tests
```

Or with Docker (no local Python required):

```bash
cp .env.example .env          # fill in what you have
docker compose up
```

The Temporal UI will be at http://localhost:8233.

---

## Workflow changes and replay tests

If you change `workflows/package_triage_workflow.py` or `workflows/pr_action_workflow.py`, regenerate the replay fixtures:

```bash
temporal server start-dev   # must be running — generator executes real workflows
uv run python tests/generate_fixtures.py
```

Commit the updated files in `tests/fixtures/`. The CI `pytest` run will catch any determinism regression.

See [architecture.md](architecture.md#workflow-determinism-and-replay-tests) for the design rationale.

---

## Swapping the classifier

The built-in classifiers (`AnthropicClassifier`, `RuleBasedClassifier`) are selected automatically based on whether `ANTHROPIC_API_KEY` is set. You can override either choice or supply your own engine.

**Force a built-in by name** (useful to pin rule-based even when a key is present):

```env
# .env
CLASSIFIER=rule_based   # or: claude
```

**Add a new built-in classifier to this repo:**

1. Create `classifiers/{name}.py` with a class implementing `async def classify(self, signals: PackageChecks) -> Verdict`
2. In `classifiers/__init__.py`, add an entry to `_BUILTIN_CLASSIFIERS`
3. Write tests following the patterns in `tests/test_classifier.py`

**Register a third-party classifier** in a plugin package — see [extending.md](extending.md#classifier-plugins).

---

## Design principles

- **Graceful degradation** — missing API keys or upstream errors produce degraded check defaults, not a crash. This is enforced at two levels: each activity catches its own errors and returns a zero-state model; the workflow's `asyncio.gather` uses `return_exceptions=True` so a single failing activity never discards the other ten results.
- **Attacker-controlled data stays sandboxed** — package descriptions, socket alert strings, release notes, and diff content go into clearly-labelled XML tags in the LLM prompt and are explicitly named in the system prompt as untrusted.
- **No silent fallbacks** — use `ApplicationError(..., non_retryable=True)` for permanent errors (404, auth failure) so Temporal doesn't retry endlessly.
- **Archive URLs are validated** before any HTTP request — add new CDN hosts to `ALLOWED_CDN_HOSTS`, never skip the `validate_archive_url()` call.
- **Checks are nested, not flat** — `PackageChecks` holds typed sub-models (`signals.age.release_age_hours`, not `signals.release_age_hours`). Field name collisions between checks are structurally impossible.
- **The registry is the source of truth** — `_CHECK_REGISTRY` in `package_triage_workflow.py` drives the gather order, the `CHECK_ACTIVITY_NAMES` constant, and the worker registration test. When adding a check, the registry row is the one required workflow-layer edit.
- **Worker registration is automatic** — `worker.py` scans `checks/*.py` and `platform/*.py` at startup for `@activity.defn`-decorated functions. Creating a new activity file is sufficient; no manual entry in `ACTIVITIES` is needed.
- **Ecosystem provider registration is automatic** — `get_provider()` scans `ecosystems/*.py` for classes with an `ecosystem_name` attribute, then checks the `dependency_scout.ecosystems` entry points group for installed plugins. Creating a new provider file (or installing a plugin package) is sufficient; no manual registration is needed.

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
- [x] Custom check plugin architecture — third-party checks via `dependency_scout.checks` entry points, no Temporal internals required, surfaced to LLM automatically
- [x] Temporal Cloud support — TLS credentials in `.env`, no code changes needed vs local dev
- [x] Renovate full support — title variants with/without `dependency` keyword, arrow and from/to body extraction, pre-release versions, false-positive prevention
