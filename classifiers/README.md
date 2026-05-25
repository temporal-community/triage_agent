# Classifiers

A classifier takes all the checks gathered by `PackageTriageWorkflow` and produces a **GREEN / YELLOW / RED** verdict with a human-readable explanation. Swapping classifiers is how you trade cost, latency, and accuracy against each other.

## Built-in classifiers

| File | Class | What drives it | Required config |
|---|---|---|---|
| `anthropic.py` | `AnthropicClassifier` | Anthropic API | `ANTHROPIC_API_KEY`; optionally `ANTHROPIC_MODEL` (default: `claude-sonnet-4-6`) |
| `openai.py` | `OpenAIClassifier` | OpenAI API | `OPENAI_API_KEY`; optionally `OPENAI_MODEL` (default: `gpt-5.5`) |
| `ollama.py` | `OllamaClassifier` | Local [Ollama](https://ollama.com) instance — no API key needed | `OLLAMA_HOST` (default: `http://localhost:11434`) and `OLLAMA_MODEL` (default: `llama4`) |
| `_helpers.py` | `RuleBasedClassifier` (via `__init__.py`) | Deterministic threshold rules — zero API keys, zero cost | Nothing |

## How a classifier is selected

At startup, `get_classifier()` in `__init__.py` picks one in this order:

1. `CLASSIFIER` env var — matched against the `dependency_scout.classifiers` entry point group first, then built-in names (`claude`, `openai`, `ollama`, `rule_based`)
2. `ANTHROPIC_API_KEY` is set → `AnthropicClassifier`
3. Fallback → `RuleBasedClassifier`

So zero config gets you a working (rule-based) system, and adding `ANTHROPIC_API_KEY` upgrades it to LLM classification automatically.

## Adding a new built-in classifier

**Step 1 — create the module**

```python
# classifiers/gemini.py
import os
from models import PackageChecks, Verdict
from classifiers._helpers import _build_message, _rule_based

class GeminiClassifier:
    async def classify(self, signals: PackageChecks) -> Verdict:
        prompt = _build_message(signals)
        # ... call the Gemini API, parse the response into a Verdict ...
```

`_build_message(signals)` returns the fully-formatted prompt string that all LLM classifiers use — reuse it so the LLM gets consistent context regardless of which backend is running.

**Step 2 — register the name**

In `classifiers/__init__.py`, add an entry to `_BUILTIN_CLASSIFIERS`:

```python
_BUILTIN_CLASSIFIERS: dict[str, type] = {
    "claude":      AnthropicClassifier,
    "openai":      OpenAIClassifier,
    "ollama":      OllamaClassifier,
    "rule_based":  RuleBasedClassifier,
    "gemini":      GeminiClassifier,   # ← add this
}
```

And import it at the top of the file:

```python
from classifiers.gemini import GeminiClassifier
```

**Step 3 — write tests**

Add a test file under `tests/` following the patterns in `tests/test_classifier.py`. Mock the external API call; verify that a GREEN, YELLOW, and RED response each maps to the right `Verdict.classification`.

## Adding an external plugin classifier

For classifiers distributed as separate packages, use the entry point path instead:

```toml
# pyproject.toml of your plugin package
[project.entry-points."dependency_scout.classifiers"]
my_gemini = "my_package:GeminiClassifier"
```

Then set `CLASSIFIER=my_gemini` in `.env`. The class must implement `async def classify(self, signals: PackageChecks) -> Verdict`.
