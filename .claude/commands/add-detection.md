Add a new supply chain attack detection pattern to the Scout.

If the user provided arguments ($ARGUMENTS), treat them as a description of what to detect (attack name, behaviour, or package involved). Otherwise ask: "What attack or behaviour do you want to detect? (e.g. 'npm credential theft', 'Python .pth persistence', a CVE or blog post link)"

Once you have a description, ask clarifying questions only if you cannot determine the answers from context:

1. **Which kind of pattern is this?**
   - Network call in library code (outbound HTTP) → `detections/net_calls.yaml`
   - Obfuscated/encoded payload → `detections/obfuscation.yaml`
   - OS persistence, self-propagation, credential theft → `detections/persistence.yaml`
   - Suspicious file name or binary type → `detections/file_types.yaml`

2. **Which language/extension?** (only for net_calls.yaml — it's keyed by file extension)

---

## Where to add it

### New network call pattern — `detections/net_calls.yaml`

Find the block for the file extension (`.py`, `.js`, `.ts`, `.rb`, etc.) and add:

```yaml
- pattern: 'YourRegexHere'
  desc: what this detects and why it matters
```

Use **single-quoted** YAML strings for regex — single quotes never process backslash escapes, so `\b` and `\.` work as-is without doubling.

If the extension doesn't exist yet, add a new block at the end:

```yaml
.ext:
- pattern: 'SomeHTTPClient\b'
  desc: HTTP client library for SomeLang
```

### OS persistence or worm propagation — `detections/persistence.yaml`

Persistence goes under `patterns:`:

```yaml
- pattern: 'some\.persistence\.path'
  desc: short-name (Attack/Repo/Date reference if known)
```

Worm propagation is a **compound rule** — the file must contain BOTH `credential_read` AND `publish_endpoint` to trigger. If the new attack has a two-step pattern, update both sub-keys under `worm_propagation:`.

### Obfuscation — `detections/obfuscation.yaml`

Keyed by extension, same format as net_calls.yaml.

### Suspicious file names/types — `detections/file_types.yaml`

Add to `suspicious_filenames:`, `suspicious_path_prefixes:`, `dangerous_binary_suffixes:`, or `install_hook_names:` as appropriate.

---

## Step — Add a test

Open `tests/test_detections.py` and add a test that checks your pattern actually matches a sample string, for example:

```python
def test_my_new_pattern_matches():
    # .py network call
    sample = "import my_new_http_lib"
    assert any(p.search(sample) for p in NET_CALL_PATTERNS.get(".py", []))
```

Run:

```bash
uv run pytest tests/test_detections.py -v
```

---

## Step — Run the full suite

```bash
uv run ruff format detections/ tests/test_detections.py
uv run pytest -x -q
```

---

## Common pitfalls

- **Backslash doubling in YAML** — single-quoted strings (`'...'`) preserve regex backslashes literally. Double-quoted strings require `\\b`, `\\.`, etc. Always use single quotes.
- **Too-broad patterns** — a pattern like `http` will match half the codebase. Prefer `\bhttplib2\b`, `requests\.get\b`, etc.
- **Wrong file** — persistence patterns in net_calls.yaml (or vice versa) won't affect the right classifier signal.
- **Compound worm rule** — the worm fires only when BOTH `credential_read` AND `publish_endpoint` appear in the **same file**. If you're describing a single-step attack, use a plain persistence pattern instead.
