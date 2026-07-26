"""ESP abstraction (port of packages/core/src/email/provider.ts).

The `log` provider is the keyless default: it does NOT drop the email — the
rendered HTML is persisted on MessageLog by the calling activity and browsable
at /dev/emails, which is what makes the whole demo runnable without an ESP.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from ..config import settings
from ..logging import logger


@dataclass
class SendArgs:
    to: str
    from_: str
    subject: str
    html: str
    text: str
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class SendResult:
    provider_message_id: str
    provider: str


class EmailProvider:
    name: str = "base"

    async def send(self, args: SendArgs) -> SendResult:  # pragma: no cover - abstract
        raise NotImplementedError


class LogEmailProvider(EmailProvider):
    name = "log"

    async def send(self, args: SendArgs) -> SendResult:
        logger.info(
            "[email:log] rendered email (view at /dev/emails)",
            to=args.to,
            subject=args.subject,
            bytes=len(args.html),
        )
        rid = f"log_{int(time.time() * 1000)}_{random.randbytes(3).hex()}"
        return SendResult(provider_message_id=rid, provider="log")


class ResendEmailProvider(EmailProvider):
    name = "resend"

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    async def send(self, args: SendArgs) -> SendResult:
        async with httpx.AsyncClient(timeout=15) as client:
            res = await client.post(
                "https://api.resend.com/emails",
                headers={"Authorization": f"Bearer {self._api_key}"},
                json={
                    "to": args.to,
                    "from": args.from_,
                    "subject": args.subject,
                    "html": args.html,
                    "text": args.text,
                    "headers": args.headers or {},
                },
            )
        if res.status_code >= 300:
            raise RuntimeError(f"resend: {res.status_code} {res.text}")
        data = res.json()
        return SendResult(provider_message_id=data.get("id", "unknown"), provider="resend")


class SesEmailProvider(EmailProvider):
    """AWS SESv2 sender. Credentials come from the standard boto3 chain
    (env vars / shared config / IAM role); only the region is configured.
    `aioboto3` is imported lazily so it stays an optional dependency."""

    name = "ses"

    def __init__(self, region: str, configuration_set: str | None = None) -> None:
        self._region = region
        self._configuration_set = configuration_set

    async def send(self, args: SendArgs) -> SendResult:
        try:
            import aioboto3
        except ImportError as err:  # pragma: no cover - depends on optional extra
            raise RuntimeError("EMAIL_PROVIDER=ses requires the 'aioboto3' package") from err

        request: dict[str, Any] = {
            "FromEmailAddress": args.from_,
            "Destination": {"ToAddresses": [args.to]},
            "Content": {
                "Simple": {
                    "Subject": {"Data": args.subject, "Charset": "UTF-8"},
                    "Body": {
                        "Html": {"Data": args.html, "Charset": "UTF-8"},
                        "Text": {"Data": args.text, "Charset": "UTF-8"},
                    },
                }
            },
        }
        if self._configuration_set:
            request["ConfigurationSetName"] = self._configuration_set

        session = aioboto3.Session()
        async with session.client("sesv2", region_name=self._region) as client:
            resp = await client.send_email(**request)
        return SendResult(provider_message_id=resp.get("MessageId", "unknown"), provider="ses")


def get_email_provider(org_settings: dict[str, Any] | None = None) -> EmailProvider:
    """Per-org `settings.emailProvider` wins, else the env default; degrades to log."""
    s = settings()
    choice = (org_settings or {}).get("emailProvider") or s.EMAIL_PROVIDER

    if choice == "resend" and s.RESEND_API_KEY:
        return ResendEmailProvider(s.RESEND_API_KEY)
    if choice == "ses":
        return SesEmailProvider(s.AWS_REGION, s.SES_CONFIGURATION_SET)
    if choice == "resend" and not s.RESEND_API_KEY:
        logger.warning("EMAIL_PROVIDER=resend but RESEND_API_KEY missing — using log provider")
    return LogEmailProvider()
