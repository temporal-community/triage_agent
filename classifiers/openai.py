"""OpenAIClassifier — uses the OpenAI chat completions API to classify package signals."""

import json
import os

from temporalio import activity

from models import PackageChecks, Verdict
from helpers.prompts import CLASSIFIER_SYSTEM
from classifiers._helpers import _build_message, _rule_based


class OpenAIClassifier:
    """Uses the OpenAI chat completions API (gpt-5.5 by default). No extra packages required."""

    async def classify(self, signals: PackageChecks) -> Verdict:
        import httpx as _httpx

        api_key = os.environ.get("OPENAI_API_KEY", "")
        model = os.environ.get("OPENAI_MODEL", "gpt-5.5")
        try:
            async with _httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": model,
                        "messages": [
                            {"role": "system", "content": CLASSIFIER_SYSTEM},
                            {"role": "user", "content": _build_message(signals)},
                        ],
                        "tools": [
                            {
                                "type": "function",
                                "function": {
                                    "name": "submit_verdict",
                                    "description": "Submit your supply chain risk classification",
                                    "parameters": Verdict.model_json_schema(),
                                },
                            }
                        ],
                        "tool_choice": {
                            "type": "function",
                            "function": {"name": "submit_verdict"},
                        },
                    },
                )
                resp.raise_for_status()
            tool_call = resp.json()["choices"][0]["message"]["tool_calls"][0]
            verdict = Verdict(**json.loads(tool_call["function"]["arguments"]))
        except Exception as exc:
            activity.logger.warning(
                "OpenAI classifier failed (%r), falling back to rule-based", exc
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
