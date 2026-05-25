# Contributing

## Adding a detection pattern for a new attack

This is the lowest-barrier contribution: a two-line YAML edit, no Python required.

Detection patterns (regex strings that flag suspicious code in package diffs) live in `detections/`:

| File | What it covers |
|---|---|
| `net_calls.yaml` | Outbound network calls in library code, by language extension |
| `obfuscation.yaml` | Encoded payloads, zero-width Unicode tricks |
| `persistence.yaml` | OS persistence mechanisms, npm worm propagation |
| `file_types.yaml` | Suspicious filenames, dangerous binary extensions |

Add a pattern — for example, a new HTTP client library that a recent attack used:

```yaml
# detections/net_calls.yaml, under the .py block:
- pattern: 'evil_http\.fetch\b'
  desc: EvilHTTP library used in SupplyChainCorp May 2026 attack
```

Use **single-quoted** YAML strings for regex — backslashes work as-is without doubling.

Run `uv run pytest tests/test_detections.py -v` to verify your pattern compiles. Then run the full suite (`uv run pytest -x -q`).

Use the `/add-detection` Claude Code skill for a guided walkthrough in Claude Code.

---

## Adding a new ecosystem

The plugin architecture makes this straightforward. Adding Composer, NuGet, or any other ecosystem is approximately 150 lines in one file.

**Step 1 — Create `ecosystems/{name}.py`**

Implement the `EcosystemProvider` Protocol. Copy an existing provider (e.g. `rubygems.py`) as a starting point. Set `ecosystem_name` to the canonical key used everywhere else — `get_provider()` discovers it automatically:

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

**Step 2 — Tests**

Add a test section for your ecosystem following the existing npm/rubygems patterns in `tests/test_activities.py`. Each method needs at minimum: success case, 404/not-found case, and (for attestations) a no-attestation case. Aim to keep overall coverage above 95%.

---

## Adding a new check

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

**Step 2 — Create `activities/my_new_check.py`**

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

Tests are isolated automatically — a `conftest.py` fixture clears all caches before and after each test, so you don't need to worry about cache state leaking between tests.

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

---

## Swapping the classifier

The built-in classifiers (`AnthropicClassifier`, `RuleBasedClassifier`) are selected automatically based on whether `ANTHROPIC_API_KEY` is set. You can override either choice or supply your own engine.

**Force a built-in by name** (useful to pin rule-based even when a key is present):

```env
# .env
CLASSIFIER=rule_based   # or: claude
```

**Register a third-party classifier** in your plugin package:

```python
# my_package/__init__.py
from models import PackageChecks, Verdict

class OpenAIClassifier:
    async def classify(self, signals: PackageChecks) -> Verdict:
        # call OpenAI, return Verdict(...)
        ...
```

```toml
# pyproject.toml
[project.entry-points."dependency_scout.classifiers"]
my_openai = "my_package:OpenAIClassifier"
```

Then set `CLASSIFIER=my_openai` in `.env`. The worker picks it up automatically — no code changes needed.

The classifier receives the full `PackageChecks` object including `custom_checks` (plugin check activity results). Return a `Verdict` with `classification`, `confidence`, `reasoning`, and `flags`.

---

## Design principles

- **Graceful degradation** — missing API keys or upstream errors produce degraded check defaults, not a crash. This is enforced at two levels: each activity catches its own errors and returns a zero-state model; the workflow's `asyncio.gather` uses `return_exceptions=True` so a single failing activity never discards the other ten results.
- **Attacker-controlled data stays sandboxed** — package descriptions, socket alert strings, release notes, and diff content go into clearly-labelled XML tags in the LLM prompt and are explicitly named in the system prompt as untrusted.
- **No silent fallbacks** — use `ApplicationError(..., non_retryable=True)` for permanent errors (404, auth failure) so Temporal doesn't retry endlessly.
- **Archive URLs are validated** before any HTTP request — add new CDN hosts to `ALLOWED_CDN_HOSTS`, never skip the `validate_archive_url()` call.
- **Checks are nested, not flat** — `PackageChecks` holds typed sub-models (`signals.age.release_age_hours`, not `signals.release_age_hours`). Field name collisions between checks are structurally impossible.
- **The registry is the source of truth** — `_CHECK_REGISTRY` in `package_triage_workflow.py` drives the gather order, the `CHECK_ACTIVITY_NAMES` constant, and the worker registration test. When adding a check, the registry row is the one required workflow-layer edit.
- **Worker registration is automatic** — `worker.py` scans `activities/*.py` at startup for `@activity.defn`-decorated functions. Creating a new activity file is sufficient; no manual entry in `ACTIVITIES` is needed.
- **Ecosystem provider registration is automatic** — `get_provider()` scans `ecosystems/*.py` for classes with an `ecosystem_name` attribute, then checks the `dependency_scout.ecosystems` entry points group for installed plugins. Creating a new provider file (or installing a plugin package) is sufficient; no manual registration is needed.

---

## Extending from outside this repo (plugin API)

Third-party packages can register ecosystem providers without modifying this codebase.

### Python-native plugins

Declare an entry point in your `pyproject.toml`:

```toml
[project.entry-points."dependency_scout.ecosystems"]
django_packages = "dependency_scout_django:DjangoPackagesProvider"
```

`DjangoPackagesProvider` must implement the `EcosystemProvider` Protocol: the four class attributes (`ecosystem_name`, `osv_name`, `dependabot_slug`, `name_re`) and the seven async methods. See any built-in provider in `ecosystems/` for a template.

### Non-Python bridge packages (PHP, Go, Rust, …)

If your logic lives in a non-Python stack, subclass `RemoteEcosystemProvider` from `ecosystems/remote.py`. It implements all seven protocol methods by POSTing to your service — your bridge package is ~10 lines of Python that configure the URL and ecosystem metadata:

```python
# dependency_scout_drupal/__init__.py
import re
from ecosystems.remote import RemoteEcosystemProvider

class DrupalProvider(RemoteEcosystemProvider):
    ecosystem_name  = "drupal"
    osv_name        = "Packagist"
    dependabot_slug = "drupal"
    name_re         = re.compile(r"^[a-z0-9_-]+/[a-z0-9_-]+$")
    remote_base_url = "https://drupal-bridge.example.com/triage/v1"
```

Your service must expose `POST {base_url}/{method_name}` endpoints. Each endpoint receives the method parameters as a JSON body and responds with the corresponding signal model fields as JSON. The full request/response spec is in the docstrings in `ecosystems/remote.py`.

### Adding custom checks

Plugins can contribute extra supply-chain checks via a clean entry-point API — no Temporal internals required. Declare an async function and register it in `pyproject.toml`:

```python
# dependency_scout_drupal/vuln_check.py
from models import CheckContext

async def run(ctx: CheckContext) -> dict:
    """ctx has: package, ecosystem, old_version, new_version."""
    result = await my_internal_db.lookup(ctx.package, ctx.ecosystem)
    return {"internal_vuln_count": result.count}
```

```toml
# pyproject.toml
[project.entry-points."dependency_scout.checks"]
drupal_vuln = "dependency_scout_drupal.vuln_check:run"
```

The `activities.custom_checks.run_all` activity discovers all installed `dependency_scout.checks` entry points at runtime and runs them in parallel. Results land in `PackageChecks.custom_checks` under the entry-point name and are surfaced to the LLM in a sandboxed `<untrusted_custom>` block — the same way package descriptions and diff content are handled. They cannot override or poison the core trusted checks.

No config file changes are needed in target repos — plugins are discovered automatically from the installed packages.

**How the classifier handles your check results:**

- **LLM classifiers (Claude, OpenAI, Ollama)** — your results appear automatically in the prompt as labeled JSON. The LLM reasons over them without any code changes on your part. No schema registration needed; the LLM infers meaning from the key names and values.
- **Rule-based classifier** — ignores `custom_checks` by design. Deterministic threshold rules can only be written for checks whose structure is known at compile time. If you need rule-based support for your check, contribute it as a built-in check (see "Adding a new check" above) rather than a plugin.

This means plugins work best when an LLM classifier is configured. The rule-based fallback will still run and post a verdict — it just won't factor in your custom check.

### In both cases

Once installed, `get_provider("drupal")` returns your provider and custom checks run automatically — no changes to this repo needed. Built-in providers take precedence over plugins with the same `ecosystem_name`, so core ecosystems cannot be shadowed.

**Security note:** both entry point groups (`dependency_scout.ecosystems` and `dependency_scout.checks`) load plugin code into the same process as the core worker. This is the same trust boundary as any `pip install` dependency — the operator who deploys Dependency Scout is implicitly trusting the packages they install. Plugin results in `custom_checks` are rendered in the sandboxed `<untrusted_custom>` section of the LLM prompt and cannot influence the trusted checks block.

### Advanced checks via `dependency_scout.activity_checks`

For checks that need full Temporal control — heartbeating, custom retry policies, or activity-level cancellation — use the advanced plugin path. The built-in `activities/package_diff.py` is the reference example: it downloads and diffs package archives, requiring a 2-minute start-to-close timeout and a 45-second heartbeat timeout to detect stuck downloads.

```python
# my_plugin/activities.py
from temporalio import activity
from models import CheckContext

@activity.defn(name="my_company.deep_archive_scan")
async def deep_archive_scan(ctx: CheckContext) -> dict:
    # Call activity.heartbeat() periodically for long-running work
    activity.heartbeat()
    # ... long-running analysis ...
    return {"suspicious_patterns": ["..."]}
```

```toml
# pyproject.toml
[project.entry-points."dependency_scout.activity_checks"]
deep_scan = "my_plugin.activities:deep_archive_scan"
```

```yaml
# .github/dependency-scout.yml (opt-in per repo)
extra_check_activities:
  - my_company.deep_archive_scan
```

The worker auto-discovers and registers `@activity.defn` functions from all `dependency_scout.activity_checks` entry points at startup. Per-repo opt-in via `extra_check_activities` is required — the activity is available to the worker but only invoked for repos that list it. Results are merged into `PackageChecks.custom_checks` under the activity name string (from `@activity.defn`).

**When to use each plugin path:**

- **`dependency_scout.checks`** — fast API calls, <30 seconds, no Temporal knowledge needed. Plain `async def run(ctx) -> dict`.
- **`dependency_scout.activity_checks`** — long-running work (archive downloads, corpus scanning), needs heartbeating or custom retry. Requires `@activity.defn` and Temporal knowledge. Modelled on `activities/package_diff.py`.
