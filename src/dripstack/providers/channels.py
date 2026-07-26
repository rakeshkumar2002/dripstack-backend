"""Channel senders (port of packages/core/src/channels.ts).

Email is handled in the worker activity via the render engine + EmailProvider.
Slack & Teams deliver natively via per-org **Incoming Webhook URLs**
(`ChannelIntegration`); when a channel isn't configured the stub sender just
logs (mirroring the keyless `LogEmailProvider`) so the demo runs without creds.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import httpx

from ..logging import logger


@dataclass
class ChannelResult:
    id: str


def _plain(text: str, limit: int = 2900) -> str:
    t = (text or "").strip()
    return t if len(t) <= limit else t[: limit - 1] + "…"


class ChannelSender:
    channel: str = "base"

    async def send(
        self, *, to: str, subject: str, html: str, text: str, link: str | None = None
    ) -> ChannelResult:
        raise NotImplementedError


# ── Stubs (fallback when a channel isn't configured) ──────────────────────────


class SlackStubSender(ChannelSender):
    channel = "slack"

    async def send(self, *, to: str, subject: str, html: str, text: str, link: str | None = None) -> ChannelResult:
        logger.info("[channel:slack] (stub) would post Block Kit message", to=to, subject=subject)
        return ChannelResult(id=f"slack_stub_{int(time.time() * 1000)}")


class TeamsStubSender(ChannelSender):
    channel = "teams"

    async def send(self, *, to: str, subject: str, html: str, text: str, link: str | None = None) -> ChannelResult:
        logger.info("[channel:teams] (stub) would POST Adaptive Card", to=to, subject=subject)
        return ChannelResult(id=f"teams_stub_{int(time.time() * 1000)}")


# ── Native webhook senders ────────────────────────────────────────────────────


class SlackWebhookSender(ChannelSender):
    channel = "slack"

    def __init__(self, webhook_url: str) -> None:
        self._url = webhook_url

    def build_payload(self, *, subject: str, text: str, link: str | None) -> dict:
        blocks: list[dict] = [
            {"type": "header", "text": {"type": "plain_text", "text": _plain(subject, 150), "emoji": True}},
            {"type": "section", "text": {"type": "mrkdwn", "text": _plain(text)}},
        ]
        if link:
            blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": f"<{link}|View run details>"}]})
        return {"text": _plain(subject, 150), "blocks": blocks}

    async def send(self, *, to: str, subject: str, html: str, text: str, link: str | None = None) -> ChannelResult:
        payload = self.build_payload(subject=subject, text=text, link=link)
        async with httpx.AsyncClient(timeout=15) as client:
            res = await client.post(self._url, json=payload)
        if res.status_code >= 300:
            raise RuntimeError(f"slack: {res.status_code} {res.text}")
        return ChannelResult(id=f"slack_{int(time.time() * 1000)}")


class TeamsWebhookSender(ChannelSender):
    channel = "teams"

    def __init__(self, webhook_url: str) -> None:
        self._url = webhook_url

    def build_payload(self, *, subject: str, text: str, link: str | None) -> dict:
        card: dict = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": "2F5FD0",
            "summary": _plain(subject, 150),
            "title": _plain(subject, 150),
            "text": _plain(text),
        }
        if link:
            card["potentialAction"] = [
                {
                    "@type": "OpenUri",
                    "name": "View run details",
                    "targets": [{"os": "default", "uri": link}],
                }
            ]
        return card

    async def send(self, *, to: str, subject: str, html: str, text: str, link: str | None = None) -> ChannelResult:
        payload = self.build_payload(subject=subject, text=text, link=link)
        async with httpx.AsyncClient(timeout=15) as client:
            res = await client.post(self._url, json=payload)
        if res.status_code >= 300:
            raise RuntimeError(f"teams: {res.status_code} {res.text}")
        return ChannelResult(id=f"teams_{int(time.time() * 1000)}")


_STUBS = {"teams": TeamsStubSender, "slack": SlackStubSender}
_WEBHOOK = {"teams": TeamsWebhookSender, "slack": SlackWebhookSender}


def get_stub_sender(channel: str) -> ChannelSender:
    return _STUBS.get(channel, SlackStubSender)()


def get_channel_sender(channel: str, integration=None) -> ChannelSender:
    """Real webhook sender when the channel is configured + enabled, else the stub."""
    if integration is not None and getattr(integration, "enabled", False) and getattr(integration, "webhook_url", None):
        factory = _WEBHOOK.get(channel)
        if factory is not None:
            return factory(integration.webhook_url)
    return get_stub_sender(channel)
