Create a standalone check plugin package for dependency-scout.

Use this when you want to add a custom supply-chain check as a separate
installable package — for example, an internal vulnerability database lookup,
a proprietary license scanner, or a deep archive analysis that doesn't belong
in the core.

If the user provided arguments ($ARGUMENTS), treat them as a description of
what the check will do. Otherwise ask: "What will this check do? (e.g.
'look up packages in our internal vuln DB', 'scan archive contents for
proprietary license markers', 'fetch SBOM from internal registry')"

---

## Step 1 — Choose the right tier

Ask (or infer from context):

**Tier A — Simple check** (`dependency_scout.checks`)
- Plain `async def` — no Temporal knowledge required
- Runs in parallel with all other checks; must finish in under ~30 seconds
- Use this for: API lookups, database queries, lightweight analysis

**Tier B — Advanced check** (`dependency_scout.activity_checks`)
- Full Temporal `@activity.defn` — heartbeating, custom retry/timeout policies, cancellation
- Requires per-repo opt-in in `.github/dependency-scout.yml`
- Use this for: archive downloads, corpus scanning, anything that could take minutes or needs retry control

When in doubt, suggest Tier A. Suggest Tier B only if the user mentions timeouts, heartbeating, long-running work, or archive/binary downloads.

---

## Step 2 — Scaffold the package

Suggest a name like `dependency-scout-{org}-checks` or `dependency-scout-{topic}`.

```
my-plugin/
├── pyproject.toml
└── my_plugin/
    ├── __init__.py        ← empty or minimal
    └── checks.py          ← the check implementation
```

---

## Step 3A — Tier A: Simple check

### `my_plugin/checks.py`

```python
from models import CheckContext

async def run(ctx: CheckContext) -> dict:
    """
    ctx fields: ctx.package, ctx.ecosystem, ctx.old_version, ctx.new_version
    Return a dict — keys become fields in PackageChecks.custom_checks.
    """
    result = await my_internal_db.lookup(ctx.package, ctx.ecosystem)
    return {
        "internal_vuln_count": result.count,
        "severity": result.max_severity,
    }
```

Return a plain `dict`. Keys are arbitrary — choose names that will be
meaningful in the LLM classifier prompt. Values must be JSON-serialisable.

On failure, catch exceptions and return a degraded default rather than
raising — the Scout treats any exception from a custom check as a
non-fatal warning:

```python
async def run(ctx: CheckContext) -> dict:
    try:
        result = await my_internal_db.lookup(ctx.package, ctx.ecosystem)
        return {"internal_vuln_count": result.count}
    except Exception:
        return {"internal_vuln_count": None}
```

### `pyproject.toml`

```toml
[project]
name = "dependency-scout-my-checks"
version = "0.1.0"
dependencies = ["dependency-scout"]

[project.entry-points."dependency_scout.checks"]
my_check = "my_plugin.checks:run"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
```

The entry-point name (`my_check` above) is the key your results are stored
under in `PackageChecks.custom_checks`. Choose something unique and
descriptive — it appears verbatim in the LLM classifier prompt.

### How classifiers handle your results

- **LLM classifiers (Claude, OpenAI, Ollama)** — your dict is injected
  automatically into the prompt as labeled JSON in a `<untrusted_custom>`
  block. No code changes needed.
- **Rule-based classifier** — ignores `custom_checks` by design. If you need
  rule-based support, contribute the check as a built-in (see contributing.md).

No config changes are needed in target repos — plugins are discovered
automatically from installed packages.

---

## Step 3B — Tier B: Advanced check

### `my_plugin/checks.py`

```python
from temporalio import activity
from models import CheckContext

@activity.defn(name="my_company.deep_archive_scan")
async def deep_archive_scan(ctx: CheckContext) -> dict:
    # Call activity.heartbeat() periodically so Temporal knows you're alive.
    # Without this, a stuck download silently times out.
    activity.heartbeat()

    # ... long-running analysis ...
    data = await download_and_scan(ctx.package, ctx.new_version)

    activity.heartbeat()  # call again after expensive steps
    return {"suspicious_patterns": data.patterns, "risk_score": data.score}
```

The `name=` string in `@activity.defn` must be **globally unique** across all
installed plugins. Use a namespaced format: `org.check_name`.

### `pyproject.toml`

```toml
[project]
name = "dependency-scout-my-checks"
version = "0.1.0"
dependencies = ["dependency-scout", "temporalio"]

[project.entry-points."dependency_scout.activity_checks"]
deep_scan = "my_plugin.checks:deep_archive_scan"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
```

### Per-repo opt-in

Unlike simple checks, activity checks require explicit opt-in in each repo's
`.github/dependency-scout.yml`:

```yaml
extra_check_activities:
  - my_company.deep_archive_scan   # must match the @activity.defn name exactly
```

The activity is registered with the worker at startup for all repos, but only
called for repos that list it here.

---

## Step 4 — Install and verify

```bash
# Install your plugin into the Scout's environment
uv pip install -e ../my-plugin

# Verify the entry point is registered
python -c "
from importlib.metadata import entry_points
# Change group to 'dependency_scout.activity_checks' for Tier B
eps = entry_points(group='dependency_scout.checks')
print([ep.name for ep in eps])
"
```

For Tier A, run a quick triage to confirm your check fires and results appear:

```bash
uv run python triage.py --ecosystem pip --package requests --old 2.31.0 --new 2.32.0
```

Your check's results will appear in the verdict output under `custom_checks`.

---

## Step 5 — Test your check

```python
import pytest
from temporalio.testing import ActivityEnvironment
from models import CheckContext
from my_plugin.checks import run  # or deep_archive_scan for Tier B

@pytest.mark.asyncio
async def test_my_check_success():
    env = ActivityEnvironment()
    ctx = CheckContext(
        package="requests",
        ecosystem="pip",
        old_version="2.31.0",
        new_version="2.32.0",
    )
    result = await env.run(run, ctx)
    assert "internal_vuln_count" in result

@pytest.mark.asyncio
async def test_my_check_degrades_on_failure(monkeypatch):
    # Simulate the external service being down
    monkeypatch.setattr("my_plugin.checks.my_internal_db", broken_db)
    env = ActivityEnvironment()
    ctx = CheckContext(package="requests", ecosystem="pip",
                       old_version="2.31.0", new_version="2.32.0")
    result = await env.run(run, ctx)
    assert result["internal_vuln_count"] is None  # degraded, not raised
```

---

## Common pitfalls

- **Tier B: plain async function silently skipped** — if you forget `@activity.defn`, the worker logs a WARNING and skips your check entirely. If your check isn't running, check the logs first.
- **Tier B: `@activity.defn` name collision** — two plugins with the same `name=` string cause a registration error at worker startup. Always namespace: `my_company.check_name`.
- **Tier B: no `extra_check_activities` in repo config** — the activity is registered but never called. This is intentional (opt-in), not a bug.
- **Return non-serialisable types** — `datetime`, custom objects, etc. will cause serialisation errors. Stick to strings, numbers, lists, dicts, and `None`.
- **Raising instead of degrading** — an unhandled exception in a simple check is caught by `run_all` and logged as a warning; the check result is omitted. In an activity check, Temporal will retry it according to the retry policy. Either way, prefer returning a degraded dict over raising.
- **Entry point name conflicts** — two plugins with the same entry-point name (e.g. both registering `my_check`) will have one silently override the other. Use org-namespaced names.
