"""Deliver one outbound webhook (port of processors/outbound.ts).

Signs the body with HMAC-SHA256 so the customer can verify authenticity. Raises
on non-2xx so the RabbitMQ consumer dead-letters it for retry/backoff.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from ...logging import logger
from ...shared import assert_safe_outbound_url, hmac_sha256_hex


async def process_outbound_job(job: dict[str, Any]) -> None:
    # Last line of defence: the URL was validated when saved, but a stored row
    # could predate the guard or its DNS could have moved since.
    assert_safe_outbound_url(job["url"])

    body = json.dumps({"event": job["event"], "data": job["data"]})
    signature = hmac_sha256_hex(job["secret"], body)

    async with httpx.AsyncClient(timeout=15) as client:
        res = await client.post(
            job["url"],
            content=body,
            headers={
                "content-type": "application/json",
                "x-dripstack-event": job["event"],
                "x-dripstack-signature": f"sha256={signature}",
            },
        )

    if res.status_code >= 300:
        raise RuntimeError(f"outbound webhook {job['url']} returned {res.status_code}")
    logger.bind(org_id=job["organization_id"], webhook_id=job["webhook_id"]).info(
        "outbound webhook delivered", hook_event=job["event"], status=res.status_code
    )
