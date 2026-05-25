# Extending the Scout with Plugins

Everything that varies between deployments is pluggable via Python entry points — no forking required.

Four extension points exist:

| What to extend | Entry point group | When to use |
|---|---|---|
| New package ecosystem | `dependency_scout.ecosystems` | Dependabot/Renovate opens PRs for a registry not in the built-in coverage table |
| Custom classifier | `dependency_scout.classifiers` | Different LLM or decision engine (Gemini, local model, etc.) |
| Custom checks (simple) | `dependency_scout.checks` | Fast API calls, <30 seconds, no Temporal knowledge needed |
| Custom checks (advanced) | `dependency_scout.activity_checks` | Long-running work, needs heartbeating or custom retry policies |
| New platform | `dependency_scout.platforms` | Support a new code-hosting platform (Gitea, Bitbucket, etc.) |

**Contributing vs. extending:** if your ecosystem, classifier, or check is general-purpose and you'd like it in the core, see [contributing.md](contributing.md). If it's specific to your organization or stack, the plugin path here is what you want — no changes to this repo needed.

---

## Ecosystem plugins (`dependency_scout.ecosystems`)

Use this to add support for a package registry that isn't in the built-in coverage table. The plugin provides the seven ecosystem-specific methods; the Scout handles Temporal, caching, and security.

### Python-native plugin

Inherit `EcosystemProviderBase` and register via entry points:

```toml
# pyproject.toml in your plugin package
[project.entry-points."dependency_scout.ecosystems"]
django = "my_package:DjangoProvider"
```

```python
import re
from ecosystems import EcosystemProviderBase, validate_archive_url
from models import AttestationChecks, MaintainerChecks, MetadataChecks, ReleaseAgeChecks, ReleaseChecks

class DjangoProvider(EcosystemProviderBase):
    ecosystem_name  = "django"
    osv_name        = "PyPI"           # Django packages are indexed by OSV as PyPI packages
    dependabot_slug = "django"         # Requires Renovate custom datasource — Dependabot has no native django ecosystem
    name_re         = re.compile(r"^django-[a-z][a-z0-9-]*$")  # e.g. django-crispy-forms, django-debug-toolbar

    async def fetch_metadata(self, package, old_version, new_version) -> MetadataChecks: ...
    async def fetch_release_age(self, package, new_version) -> ReleaseAgeChecks: ...
    async def fetch_maintainer(self, package, old_version, new_version) -> MaintainerChecks: ...
    async def get_archive_url(self, client, package, version) -> tuple[str, str, str] | None: ...
    def extract_archive(self, archive_bytes, filename, dest) -> None: ...
    async def fetch_attestations(self, package, old_version, new_version) -> AttestationChecks: ...
    async def fetch_release(self, package, old_version, version) -> ReleaseChecks: ...
```

`EcosystemProviderBase` is a concrete base class, not a pure Protocol. Required methods raise `NotImplementedError`; future optional check methods added to the class will have safe empty-model defaults so your provider won't break on upgrade.

`get_archive_url` returns `(url, filename, integrity_string)`. Always call `validate_archive_url(url)` before returning — this enforces the CDN allowlist. Add your registry's CDN host to `ALLOWED_CDN_HOSTS` in `ecosystems/__init__.py` if needed.

See any built-in provider in `ecosystems/` for a complete template.

### Non-Python bridge plugin (PHP, Go, Rust, …)

If your ecosystem logic lives in a non-Python stack, subclass `RemoteEcosystemProvider` from `ecosystems/remote.py`. It implements all seven protocol methods by POSTing to your service — your bridge package is ~10 lines of Python that configure the URL and ecosystem metadata:

```python
# dependency_scout_drupal/__init__.py
import re
from ecosystems.remote import RemoteEcosystemProvider

class DrupalProvider(RemoteEcosystemProvider):
    ecosystem_name  = "drupal"
    osv_name        = "Packagist"
    dependabot_slug = "drupal"         # Requires Renovate custom datasource — Dependabot has no native drupal ecosystem
    name_re         = re.compile(r"^drupal/[a-z][a-z0-9_]*$")  # e.g. drupal/views, drupal/token
    remote_base_url = "https://drupal-bridge.example.com/triage/v1"  # your PHP service wrapping api.drupal.org
```

Your service must expose `POST {base_url}/{method_name}` endpoints. Each endpoint receives the method parameters as a JSON body and responds with the corresponding check model fields as JSON. The full request/response spec is in the docstrings in `ecosystems/remote.py`.

```php
<?php
// PHP service (pseudo-code) — any framework works
$router->post('/triage/v1/{method}', function (string $method, array $body): array {
    return match ($method) {
        'fetch_metadata'     => fetch_metadata($body),
        'fetch_release_age'  => fetch_release_age($body),
        'fetch_maintainer'   => fetch_maintainer($body),
        'get_archive_url'    => get_archive_url($body),
        'fetch_attestations' => fetch_attestations($body),
        'fetch_release'      => fetch_release($body),
        default              => throw new \RuntimeException("unknown method: $method"),
    };
});

// Example: one method wrapping api.drupal.org
function fetch_metadata(array $p): array {
    $info = drupal_api("/api/projects/{$p['package']}");
    return [
        'download_count'     => $info['downloads']['total'],
        'latest_version'     => $info['releases'][0]['version'],
        'first_published_at' => $info['created'],
        // ... other MetadataChecks fields; omit fields you can't fill — they default to null
    ];
}
// ... remaining methods follow the same pattern
```

**Self-hosted GitLab:** if your ecosystem hosts source on a self-hosted GitLab instance (like Drupal modules on [git.drupalcode.org](https://git.drupalcode.org)), set `GITLAB_BASE_URL=https://your-gitlab-host` and the built-in release-note and tag-signature checks will resolve against it automatically — no custom code needed for that part.

### Notes on both paths

Once installed, `get_provider("django")` returns your provider automatically — no changes to this repo needed. Built-in providers take precedence over plugins with the same `ecosystem_name`, so core ecosystems cannot be shadowed.

**Security note:** plugin code loads into the same process as the core worker. This is the same trust boundary as any `pip install` dependency — the operator deploying Dependency Scout implicitly trusts the packages they install.

---

## Classifier plugins (`dependency_scout.classifiers`)

Use this to add a different LLM or decision engine without forking the repo.

### Full worked example: Gemini classifier

**`my_gemini_classifier/__init__.py`:**

```python
import json
import os
import httpx
from dependency_scout.models import PackageChecks, Verdict
from dependency_scout.classifiers import _build_message, _rule_based

class GeminiClassifier:
    async def classify(self, signals: PackageChecks) -> Verdict:
        api_key = os.environ.get("GEMINI_API_KEY", "")
        model = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")
        prompt = _build_message(signals)  # reuse the same prompt all built-in classifiers use

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post(
                    f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
                    headers={"X-Goog-Api-Key": api_key},
                    json={
                        "contents": [{"parts": [{"text": prompt}]}],
                        "generationConfig": {"responseMimeType": "application/json"},
                    },
                )
                resp.raise_for_status()
            text = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
            return Verdict(**json.loads(text))
        except Exception:
            return _rule_based(signals)  # always fall back gracefully
```

`Verdict` has four fields your classifier must populate:

| Field | Type | Description |
|---|---|---|
| `classification` | `"green"` / `"yellow"` / `"red"` | The risk verdict |
| `confidence` | `float` (0–1) | How confident the classifier is (e.g. `0.85`) |
| `reasoning` | `str` | One paragraph explaining the verdict |
| `flags` | `list[str]` | Specific concerns, one per item (empty list for green) |

**`pyproject.toml`:**

```toml
[project]
name = "my-gemini-classifier"
dependencies = ["dependency-scout", "httpx"]

[project.entry-points."dependency_scout.classifiers"]
gemini = "my_gemini_classifier:GeminiClassifier"
```

**Install and activate:**

```bash
pip install -e .          # or uv add my-gemini-classifier
echo "CLASSIFIER=gemini" >> .env
echo "GEMINI_API_KEY=..." >> .env
```

The `get_classifier()` function discovers the entry point automatically at startup.

The classifier receives the full `PackageChecks` object including `custom_checks` (plugin check activity results). Return a `Verdict` with `classification`, `confidence`, `reasoning`, and `flags`.

---

## Platform plugins (`dependency_scout.platforms`)

Use this to add support for a new code-hosting platform (Gitea, Bitbucket, Azure DevOps, etc.).

Implement `PlatformClient` from `platforms` and register a factory function:

```toml
[project.entry-points."dependency_scout.platforms"]
gitea = "my_package:create_client"
```

```python
from models import PRContext
from platforms import PlatformClient

def create_client(pr: PRContext) -> PlatformClient:
    return GiteaClient(base_url=os.environ["GITEA_BASE_URL"])
```

The factory receives the full `PRContext` and returns any object satisfying `PlatformClient`. See `platforms/github.py` or `platforms/gitlab.py` for a complete implementation reference.

---

## Check plugins

Two paths exist depending on whether your check needs Temporal internals.

### Simple checks (`dependency_scout.checks`)

For checks that make API calls and finish in under 30 seconds. No Temporal knowledge required — just an async function:

```python
# my_plugin/vuln_check.py
from models import CheckContext

async def run(ctx: CheckContext) -> dict:
    """ctx has: package, ecosystem, old_version, new_version."""
    result = await my_internal_db.lookup(ctx.package, ctx.ecosystem)
    return {"internal_vuln_count": result.count}
```

```toml
# pyproject.toml
[project.entry-points."dependency_scout.checks"]
internal_vuln = "my_plugin.vuln_check:run"
```

The `activities.custom_checks.run_all` activity discovers all installed `dependency_scout.checks` entry points at runtime and runs them in parallel. Results land in `PackageChecks.custom_checks` under the entry-point name.

**How classifiers handle your results:**

- **LLM classifiers (Claude, OpenAI, Ollama)** — your results appear automatically in the prompt as labeled JSON in a sandboxed `<untrusted_custom>` block. The LLM reasons over them without any code changes on your part.
- **Rule-based classifier** — ignores `custom_checks` by design. If you need rule-based support for your check, contribute it as a built-in check (see [contributing.md](contributing.md)).

No config file changes are needed in target repos — plugins are discovered automatically from installed packages.

### Advanced checks (`dependency_scout.activity_checks`)

For checks that need full Temporal control — heartbeating for long-running work, custom retry policies, or activity-level cancellation. The canonical built-in example is `checks/package_diff.py`: it downloads and diffs package archives, needs a 2-minute start-to-close timeout, and uses a 45-second heartbeat timeout to detect stuck downloads.

```python
# my_plugin/activities.py
from temporalio import activity
from dependency_scout.checks import CheckContext

@activity.defn(name="my_company.deep_archive_scan")
async def deep_archive_scan(ctx: CheckContext) -> dict:
    # Call activity.heartbeat() periodically for long-running work
    activity.heartbeat()
    # ... long-running analysis ...
    return {"suspicious_patterns": [...]}
```

```toml
# pyproject.toml
[project.entry-points."dependency_scout.activity_checks"]
deep_scan = "my_plugin.activities:deep_archive_scan"
```

```yaml
# .github/dependency-scout.yml (in any repo that wants this check)
extra_check_activities:
  - my_company.deep_archive_scan
```

At worker startup, `_discover_activity_check_plugins()` loads all `dependency_scout.activity_checks` entry points and registers them alongside the built-in activities. Per-repo opt-in is required via `extra_check_activities` in the repo config — the activity is registered but only called for repos that list it. Results are merged into `PackageChecks.custom_checks` under the activity name.

### When to use each path

| Path | Use when | Temporal knowledge needed |
|---|---|---|
| `dependency_scout.checks` | Fast API calls, <30 seconds total | None — plain `async def` |
| `dependency_scout.activity_checks` | Long-running (archive downloads, corpus scanning), needs heartbeating or custom retry | Yes — requires `@activity.defn` |
