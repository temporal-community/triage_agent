"""OpenAIClassifier — uses the OpenAI chat completions API to classify package signals."""

import json
import os
from typing import Any

from temporalio import activity

from models import PackageChecks, Verdict
from helpers.prompts import CLASSIFIER_SYSTEM
from classifiers._helpers import _build_message, _rule_based

_SUBMIT_VERDICT_FUNCTION: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "submit_verdict",
        "description": "Submit your supply chain risk classification. Call this when you have enough context to make a confident verdict.",
        "parameters": Verdict.model_json_schema(),
    },
}

_WEB_SEARCH_TOOL: dict[str, Any] = {"type": "web_search_preview"}

_MAX_RESEARCH_TURNS = 5


class OpenAIClassifier:
    """Uses the OpenAI chat completions API (gpt-5.5 by default). No extra packages required.

    Runs an agentic loop: the model may use web_search_preview to research context
    before calling submit_verdict to commit to a classification.
    """

    async def classify(self, signals: PackageChecks) -> Verdict:
        import httpx as _httpx

        api_key = os.environ.get("OPENAI_API_KEY", "")
        model = os.environ.get("OPENAI_MODEL", "gpt-5.5")

        messages: list[dict[str, Any]] = [
            {"role": "system", "content": CLASSIFIER_SYSTEM},
            {"role": "user", "content": _build_message(signals)},
        ]

        try:
            async with _httpx.AsyncClient(timeout=120.0) as client:
                verdict: Verdict | None = None
                for turn in range(_MAX_RESEARCH_TURNS):
                    resp = await client.post(
                        "https://api.openai.com/v1/chat/completions",
                        headers={
                            "Authorization": f"Bearer {api_key}",
                            "Content-Type": "application/json",
                        },
                        json={
                            "model": model,
                            "messages": messages,
                            "tools": [_WEB_SEARCH_TOOL, _SUBMIT_VERDICT_FUNCTION],
                        },
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    message = data["choices"][0]["message"]
                    messages.append(message)

                    tool_calls = message.get("tool_calls") or []
                    submit_call = next(
                        (tc for tc in tool_calls if tc["function"]["name"] == "submit_verdict"),
                        None,
                    )
                    if submit_call:
                        verdict = Verdict(**json.loads(submit_call["function"]["arguments"]))
                        break

                    # No submit_verdict — check for web_search calls to continue the loop
                    search_calls = [
                        tc for tc in tool_calls if tc["function"]["name"] == "web_search_preview"
                    ]
                    if not search_calls:
                        # No tool calls at all — force submit_verdict
                        messages.append(
                            {
                                "role": "user",
                                "content": "Please call submit_verdict now with your classification.",
                            }
                        )
                        forced = await client.post(
                            "https://api.openai.com/v1/chat/completions",
                            headers={
                                "Authorization": f"Bearer {api_key}",
                                "Content-Type": "application/json",
                            },
                            json={
                                "model": model,
                                "messages": messages,
                                "tools": [_SUBMIT_VERDICT_FUNCTION],
                                "tool_choice": {
                                    "type": "function",
                                    "function": {"name": "submit_verdict"},
                                },
                            },
                        )
                        forced.raise_for_status()
                        tc = forced.json()["choices"][0]["message"]["tool_calls"][0]
                        verdict = Verdict(**json.loads(tc["function"]["arguments"]))
                        break

                    # Append tool results for web_search calls and continue
                    for tc in search_calls:
                        activity.logger.info(
                            "Classifier researching: %s (turn %d/%d)",
                            json.loads(tc["function"].get("arguments", "{}")).get("query", ""),
                            turn + 1,
                            _MAX_RESEARCH_TURNS,
                        )
                        # OpenAI returns search results inline in the assistant message content —
                        # no explicit tool result needed for web_search_preview
                        messages.append(
                            {
                                "role": "tool",
                                "tool_call_id": tc["id"],
                                "content": "Search results returned inline in assistant message.",
                            }
                        )

                if verdict is None:
                    # Exhausted turns
                    activity.logger.warning(
                        "OpenAI classifier exhausted %d research turns — forcing verdict",
                        _MAX_RESEARCH_TURNS,
                    )
                    messages.append(
                        {
                            "role": "user",
                            "content": "Please call submit_verdict now with your classification.",
                        }
                    )
                    forced = await client.post(
                        "https://api.openai.com/v1/chat/completions",
                        headers={
                            "Authorization": f"Bearer {api_key}",
                            "Content-Type": "application/json",
                        },
                        json={
                            "model": model,
                            "messages": messages,
                            "tools": [_SUBMIT_VERDICT_FUNCTION],
                            "tool_choice": {
                                "type": "function",
                                "function": {"name": "submit_verdict"},
                            },
                        },
                    )
                    forced.raise_for_status()
                    tc = forced.json()["choices"][0]["message"]["tool_calls"][0]
                    verdict = Verdict(**json.loads(tc["function"]["arguments"]))

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
