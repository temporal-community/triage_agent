import os

import anthropic
from temporalio import activity
from temporalio.exceptions import ApplicationError

from activities.models import PackageSignals, Verdict
from helpers.prompts import CLASSIFIER_SYSTEM


@activity.defn(name="activities.classifier.classify")
async def classify(signals: PackageSignals) -> Verdict:
    client = anthropic.AsyncAnthropic()
    model = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-6")

    try:
        response = await client.messages.create(
            model=model,
            max_tokens=1024,
            system=[{
                "type": "text",
                "text": CLASSIFIER_SYSTEM,
                "cache_control": {"type": "ephemeral"},
            }],
            messages=[{
                "role": "user",
                "content": f"Classify this dependency bump:\n\n{signals.model_dump_json(indent=2)}",
            }],
            tools=[{
                "name": "submit_verdict",
                "description": "Submit your supply chain risk classification",
                "input_schema": Verdict.model_json_schema(),
            }],
            tool_choice={"type": "tool", "name": "submit_verdict"},
        )
    except anthropic.AuthenticationError as exc:
        raise ApplicationError(str(exc), type="AuthenticationError", non_retryable=True) from exc
    except anthropic.BadRequestError as exc:
        raise ApplicationError(str(exc), type="BadRequestError", non_retryable=True) from exc

    tool_use = next(b for b in response.content if b.type == "tool_use")
    activity.logger.info(
        f"Classified {signals.package_name} {signals.new_version} as "
        f"{tool_use.input['classification']} ({tool_use.input['confidence']:.0%})"
    )
    return Verdict(**tool_use.input)
