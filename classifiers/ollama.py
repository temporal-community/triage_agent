"""OllamaClassifier — uses a local Ollama instance to classify package signals."""

import json
import os

from temporalio import activity

from models import PackageChecks, Verdict
from helpers.prompts import CLASSIFIER_SYSTEM
from classifiers._helpers import _build_message, _rule_based


class OllamaClassifier:
    """Uses a local Ollama instance. No API key required. Set OLLAMA_HOST and OLLAMA_MODEL."""

    async def classify(self, signals: PackageChecks) -> Verdict:
        import httpx as _httpx

        host = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
        model = os.environ.get("OLLAMA_MODEL", "llama4")
        # Ollama doesn't universally support tool calling; ask for JSON output directly.
        schema_hint = json.dumps(Verdict.model_json_schema(), indent=2)
        system = (
            CLASSIFIER_SYSTEM
            + "\n\nRespond with ONLY a single valid JSON object matching this schema "
            "(no markdown, no explanation):\n" + schema_hint
        )
        try:
            async with _httpx.AsyncClient(timeout=120.0) as client:
                resp = await client.post(
                    f"{host}/api/chat",
                    json={
                        "model": model,
                        "messages": [
                            {"role": "system", "content": system},
                            {"role": "user", "content": _build_message(signals)},
                        ],
                        "stream": False,
                        "format": "json",
                    },
                )
                resp.raise_for_status()
            verdict = Verdict(**json.loads(resp.json()["message"]["content"]))
        except Exception as exc:
            activity.logger.warning(
                "Ollama classifier failed (%r), falling back to rule-based", exc
            )
            return _rule_based(signals)
        activity.logger.info(
            "Classified %s %s as %s (%.0f%%)",
            signals.package_name,
            signals.new_version,
            verdict.classification,
            verdict.confidence * 100,
        )
        return verdict
