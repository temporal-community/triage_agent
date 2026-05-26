"""AnthropicClassifier — uses the Anthropic API to classify package signals."""

import os
from typing import Any

import anthropic
from temporalio import activity
from temporalio.exceptions import ApplicationError

from models import PackageChecks, Verdict
from helpers.prompts import CLASSIFIER_SYSTEM
from classifiers._helpers import _build_message, _rule_based

_SUBMIT_VERDICT_TOOL: dict[str, Any] = {
    "name": "submit_verdict",
    "description": "Submit your supply chain risk classification. Call this when you have enough context to make a confident verdict.",
    "input_schema": Verdict.model_json_schema(),
}

_WEB_SEARCH_TOOL: dict[str, Any] = {
    "type": "web_search_20250305",
    "name": "web_search",
}

_MAX_RESEARCH_TURNS = 5


class AnthropicClassifier:
    """Uses the Anthropic API to classify with the configured Claude model.

    Runs an agentic loop: the model may use web_search to research context
    (e.g. confirm whether obfuscated_code is a known benign bundled UI) before
    calling submit_verdict to commit to a classification.
    """

    async def classify(self, signals: PackageChecks) -> Verdict:
        client = anthropic.AsyncAnthropic()
        model = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-6")

        messages: list[dict[str, Any]] = [{"role": "user", "content": _build_message(signals)}]

        try:
            for turn in range(_MAX_RESEARCH_TURNS):
                response = await client.messages.create(  # type: ignore[arg-type]
                    model=model,
                    max_tokens=2048,
                    system=[
                        {
                            "type": "text",
                            "text": CLASSIFIER_SYSTEM,
                            "cache_control": {"type": "ephemeral"},
                        }
                    ],
                    messages=messages,  # type: ignore[arg-type]
                    tools=[_WEB_SEARCH_TOOL, _SUBMIT_VERDICT_TOOL],  # type: ignore[list-item]
                    # Don't force submit_verdict — let the model decide when to search first
                )

                # Check if model called submit_verdict
                verdict_block = next(
                    (
                        b
                        for b in response.content
                        if b.type == "tool_use" and b.name == "submit_verdict"
                    ),
                    None,
                )
                if verdict_block is not None:
                    verdict = Verdict.model_validate(verdict_block.input)
                    break

                # If stop_reason is end_turn with no tool use, force a verdict
                if response.stop_reason == "end_turn" or not any(
                    b.type == "tool_use" for b in response.content
                ):
                    activity.logger.warning(
                        "Model returned end_turn without submit_verdict on turn %d — forcing verdict call",
                        turn + 1,
                    )
                    # Force verdict on next turn
                    messages.append({"role": "assistant", "content": response.content})
                    messages.append(
                        {
                            "role": "user",
                            "content": "Please call submit_verdict now with your classification.",
                        }
                    )
                    forced = await client.messages.create(  # type: ignore[call-overload]
                        model=model,
                        max_tokens=1024,
                        system=[
                            {
                                "type": "text",
                                "text": CLASSIFIER_SYSTEM,
                                "cache_control": {"type": "ephemeral"},
                            }
                        ],
                        messages=messages,
                        tools=[_SUBMIT_VERDICT_TOOL],
                        tool_choice={"type": "tool", "name": "submit_verdict"},
                    )
                    verdict_block = next(b for b in forced.content if b.type == "tool_use")
                    verdict = Verdict.model_validate(verdict_block.input)
                    break

                # Append assistant turn and process tool results for next iteration
                messages.append({"role": "assistant", "content": response.content})
                tool_results: list[object] = []
                for block in response.content:
                    if block.type == "tool_use" and block.name == "web_search":
                        # web_search_20250305 results come back as server_tool_use;
                        # the SDK handles execution automatically and returns results
                        # in response.content as tool_result blocks — nothing to do here.
                        activity.logger.info(
                            "Classifier researching: %s (turn %d/%d)",
                            getattr(block, "input", {}).get("query", ""),
                            turn + 1,
                            _MAX_RESEARCH_TURNS,
                        )
                    elif block.type == "tool_result":
                        tool_results.append(block)

                # web_search results are already in the response content — loop continues
                if not tool_results and response.stop_reason == "tool_use":
                    # All tool uses were web_search (server-side) — no client-side results needed
                    continue
            else:
                # Exhausted turns — force a verdict
                activity.logger.warning(
                    "Classifier exhausted %d research turns — forcing verdict", _MAX_RESEARCH_TURNS
                )
                messages.append({"role": "assistant", "content": response.content})
                messages.append(
                    {
                        "role": "user",
                        "content": "Please call submit_verdict now with your classification.",
                    }
                )
                forced = await client.messages.create(  # type: ignore[call-overload]
                    model=model,
                    max_tokens=1024,
                    system=[
                        {
                            "type": "text",
                            "text": CLASSIFIER_SYSTEM,
                            "cache_control": {"type": "ephemeral"},
                        }
                    ],
                    messages=messages,
                    tools=[_SUBMIT_VERDICT_TOOL],
                    tool_choice={"type": "tool", "name": "submit_verdict"},
                )
                verdict_block = next(b for b in forced.content if b.type == "tool_use")
                verdict = Verdict.model_validate(verdict_block.input)

        except anthropic.AuthenticationError as exc:
            raise ApplicationError(
                str(exc), type="AuthenticationError", non_retryable=True
            ) from exc
        except anthropic.BadRequestError as exc:
            raise ApplicationError(str(exc), type="BadRequestError", non_retryable=True) from exc
        except Exception as exc:
            activity.logger.warning(f"LLM classifier failed ({exc!r}), falling back to rule-based")
            return _rule_based(signals)

        # Pass signals through so PRActionWorkflow can enforce per-repo gates.
        updates: dict = {}
        if verdict.release_age_hours is None:
            updates["release_age_hours"] = signals.age.release_age_hours
        if verdict.new_dependency_count == 0 and signals.diff.new_dependency_count:
            updates["new_dependency_count"] = signals.diff.new_dependency_count
        if updates:
            verdict = verdict.model_copy(update=updates)
        activity.logger.info(
            f"Classified {signals.package_name} {signals.new_version} as "
            f"{verdict.classification} ({verdict.confidence:.0%})"
        )
        return verdict
