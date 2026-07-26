"""Ingest routes (port of apps/api/src/routes/ingest.ts).

Public webhook is HMAC-authenticated; the signature is verified against the raw
request bytes (read before JSON parsing). Accepted events are buffered onto the
RabbitMQ ingest queue for the normalize worker.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request

from ...db import EventSource, EventSourceType
from ...db.session import session_scope
from ...queue import publish_ingest
from ...shared import get_by_path, verify_hmac_signature
from ..auth import AuthContext, require_api_key
from ..ratelimit import limiter

router = APIRouter(prefix="/api/v1")


def _event_type(payload: Any, fallback: str) -> str:
    t = get_by_path(payload, "$.eventType")
    return t if isinstance(t, str) and t else fallback


@router.post("/ingest/{event_source_id}", status_code=202)
@limiter.limit("120/minute")
async def ingest(
    request: Request,
    event_source_id: str,
    x_dripstack_signature: str | None = Header(default=None),
    sentry_hook_signature: str | None = Header(default=None),
):
    raw = (await request.body()).decode("utf-8")
    async with session_scope() as session:
        source = await session.get(EventSource, event_source_id)
        if source is None:
            raise HTTPException(status_code=404, detail="unknown event source")
        source_type = source.type
        signing_secret = source.signing_secret
        org_id = source.organization_id

    sig = sentry_hook_signature if source_type == EventSourceType.sentry else x_dripstack_signature
    if not verify_hmac_signature(signing_secret, raw, sig):
        raise HTTPException(status_code=401, detail="invalid signature")

    payload = json.loads(raw) if raw else {}
    await publish_ingest(
        {
            "organization_id": org_id,
            "event_source_id": event_source_id,
            "payload": payload,
            "type": _event_type(payload, f"{source_type.value}.event"),
        }
    )
    return {"accepted": True}


@router.post("/events", status_code=202)
async def events(request: Request, auth: AuthContext = Depends(require_api_key)):
    raw = (await request.body()).decode("utf-8")
    payload = json.loads(raw) if raw else {}
    await publish_ingest(
        {
            "organization_id": auth.organization_id,
            "event_source_id": None,
            "payload": payload,
            "type": _event_type(payload, "generic"),
        }
    )
    return {"accepted": True}
