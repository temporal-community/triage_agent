"""
NotificationChannel protocol — abstracts how verdicts are reported.

Default: PlatformCommentChannel posts a formatted Markdown comment to the PR/MR via
the appropriate platform client (GitHub, GitLab, …).

Opt-in extras (set env vars to activate):
  TRIAGE_NOTIFY_SLACK_WEBHOOK_URL — also POSTs a summary to a Slack incoming webhook.
  TRIAGE_NOTIFY_WEBHOOK_URL       — also POSTs raw JSON payload to a custom URL.

All active channels are combined by get_notification_channels(), which returns a
MultiChannel when more than one is configured. activities.platform.comment delegates to
get_notification_channels() so the workflow call-site never needs to change.
"""

from __future__ import annotations

import json
import os
from typing import Protocol

import httpx

from models import PRContext, PackageSignals, Verdict


class NotificationChannel(Protocol):
    """Delivers a triage verdict to some destination."""

    async def send_verdict(
        self,
        pr: PRContext,
        verdict: Verdict,
        signals: PackageSignals | None = None,
    ) -> None: ...


class PlatformCommentChannel:
    """Posts a formatted Markdown comment to the PR/MR via the appropriate platform client."""

    async def send_verdict(
        self,
        pr: PRContext,
        verdict: Verdict,
        signals: PackageSignals | None = None,
    ) -> None:
        from platforms import get_platform_client

        await get_platform_client(pr).comment(pr, verdict)


class SlackWebhookChannel:
    """Posts a brief verdict summary to a Slack incoming webhook URL.

    Activated by setting TRIAGE_NOTIFY_SLACK_WEBHOOK_URL.
    """

    def __init__(self, webhook_url: str) -> None:
        self._url = webhook_url

    async def send_verdict(
        self,
        pr: PRContext,
        verdict: Verdict,
        signals: PackageSignals | None = None,
    ) -> None:
        from temporalio import activity

        emoji = {
            "green": ":large_green_circle:",
            "yellow": ":large_yellow_circle:",
            "red": ":red_circle:",
        }.get(verdict.classification, ":white_circle:")
        if pr.platform == "gitlab":
            import os

            base = os.environ.get("GITLAB_BASE_URL", "https://gitlab.com").rstrip("/")
            pr_url = f"{base}/{pr.repo}/-/merge_requests/{pr.pr_number}"
            pr_ref = f"{pr.repo}!{pr.pr_number}"
        else:
            pr_url = f"https://github.com/{pr.repo}/pull/{pr.pr_number}"
            pr_ref = f"{pr.repo}#{pr.pr_number}"
        text = (
            f"{emoji} *{verdict.classification.upper()}* — "
            f"`{pr.package_name}` {pr.old_version}→{pr.new_version} "
            f"({pr.ecosystem}) in <{pr_url}|{pr_ref}>\n"
            f"> {verdict.reasoning[:200]}"
        )
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(self._url, json={"text": text})
                resp.raise_for_status()
        except Exception as exc:  # noqa: BLE001
            activity.logger.warning(f"Slack notification failed (non-fatal): {exc!r}")


class WebhookChannel:
    """POSTs a JSON payload to a custom URL for custom integrations.

    Payload schema: {"pr": {...}, "verdict": {...}, "signals": {...} | null}
    Activated by setting TRIAGE_NOTIFY_WEBHOOK_URL.
    """

    def __init__(self, url: str) -> None:
        self._url = url

    async def send_verdict(
        self,
        pr: PRContext,
        verdict: Verdict,
        signals: PackageSignals | None = None,
    ) -> None:
        from temporalio import activity

        payload = {
            "pr": pr.model_dump(),
            "verdict": verdict.model_dump(),
            "signals": signals.model_dump() if signals else None,
        }
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    self._url,
                    content=json.dumps(payload),
                    headers={"Content-Type": "application/json"},
                )
                resp.raise_for_status()
        except Exception as exc:  # noqa: BLE001
            activity.logger.warning(f"Webhook notification failed (non-fatal): {exc!r}")


class MultiChannel:
    """Fan-out: delivers to all configured channels, logging failures non-fatally."""

    def __init__(self, channels: list[NotificationChannel]) -> None:
        self._channels = channels

    async def send_verdict(
        self,
        pr: PRContext,
        verdict: Verdict,
        signals: PackageSignals | None = None,
    ) -> None:
        for ch in self._channels:
            await ch.send_verdict(pr, verdict, signals)


def get_notification_channels() -> NotificationChannel:
    """Return a channel (or MultiChannel) based on configured env vars."""
    channels: list[NotificationChannel] = [PlatformCommentChannel()]

    if url := os.environ.get("TRIAGE_NOTIFY_SLACK_WEBHOOK_URL"):
        channels.append(SlackWebhookChannel(url))

    if url := os.environ.get("TRIAGE_NOTIFY_WEBHOOK_URL"):
        channels.append(WebhookChannel(url))

    return channels[0] if len(channels) == 1 else MultiChannel(channels)
