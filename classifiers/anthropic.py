"""ClaudeClassifier — uses the Anthropic API to classify package signals."""

import os

import anthropic
from temporalio import activity
from temporalio.exceptions import ApplicationError

from models import PackageChecks, Verdict
from helpers.prompts import CLASSIFIER_SYSTEM
from classifiers._helpers import _build_message, _rule_based


class ClaudeClassifier:
    """Uses the Anthropic API to classify with the configured Claude model."""

    async def classify(self, signals: PackageChecks) -> Verdict:
        client = anthropic.AsyncAnthropic()
        model = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-6")

        try:
            response = await client.messages.create(
                model=model,
                max_tokens=1024,
                system=[
                    {
                        "type": "text",
                        "text": CLASSIFIER_SYSTEM,
                        "cache_control": {"type": "ephemeral"},
                    }
                ],
                messages=[{"role": "user", "content": _build_message(signals)}],
                tools=[
                    {
                        "name": "submit_verdict",
                        "description": "Submit your supply chain risk classification",
                        "input_schema": Verdict.model_json_schema(),
                    }
                ],
                tool_choice={"type": "tool", "name": "submit_verdict"},
            )
        except anthropic.AuthenticationError as exc:
            raise ApplicationError(
                str(exc), type="AuthenticationError", non_retryable=True
            ) from exc
        except anthropic.BadRequestError as exc:
            raise ApplicationError(str(exc), type="BadRequestError", non_retryable=True) from exc
        except Exception as exc:
            # Any LLM failure (rate limit, outage) — fall back to rule-based
            # rather than failing the workflow.
            activity.logger.warning(f"LLM classifier failed ({exc!r}), falling back to rule-based")
            return _rule_based(signals)

        tool_use = next(b for b in response.content if b.type == "tool_use")
        verdict = Verdict.model_validate(tool_use.input)
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
