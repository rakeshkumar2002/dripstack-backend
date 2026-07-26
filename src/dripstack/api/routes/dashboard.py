"""Authenticated, tenant-scoped dashboard API (port of routes/dashboard.ts).

Reads + light config writes. JSON response shapes must match the dashboard's
expectations exactly (camelCase keys, nested sequence/contact, _count, …).
"""

from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from ...db import (
    ApiKey,
    Contact,
    Event,
    EventSource,
    EventSourceType,
    RunStatus,
    Sequence,
    SequenceRun,
)
from ...db.analytics import compute_analytics
from ...db.tenant import TenantSession
from ...shared import sha256_hex
from ..auth import AuthContext, require_permission, require_user, tenant_db
from ..serialize import (
    api_key as ser_api_key,
)
from ..serialize import (
    contact as ser_contact,
)
from ..serialize import (
    event as ser_event,
)
from ..serialize import (
    event_source as ser_event_source,
)
from ..serialize import (
    organization as ser_org,
)
from ..serialize import (
    run_detail,
    run_row,
)
from ..serialize import (
    sequence as ser_sequence,
)

router = APIRouter(prefix="/api/v1")


# ── Runs ──────────────────────────────────────────────────────────────────────


@router.get("/runs")
async def list_runs(status: str | None = None, db: TenantSession = Depends(tenant_db)):
    criteria = []
    if status:
        try:
            criteria.append(SequenceRun.status == RunStatus(status))
        except ValueError:
            pass
    runs = await db.all(SequenceRun, *criteria, order_by=SequenceRun.started_at.desc(), limit=200)
    return {"runs": [run_row(r) for r in runs]}


@router.get("/runs/{run_id}")
async def get_run(run_id: str, db: TenantSession = Depends(tenant_db)):
    run = await db.get(SequenceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run not found")
    return {"run": run_detail(run)}


# ── Events ────────────────────────────────────────────────────────────────────


@router.get("/events")
async def list_events(db: TenantSession = Depends(tenant_db)):
    events = await db.all(Event, order_by=Event.received_at.desc(), limit=200)
    return {"events": [ser_event(e) for e in events]}


# ── Sequences ─────────────────────────────────────────────────────────────────


@router.get("/sequences")
async def list_sequences(db: TenantSession = Depends(tenant_db)):
    sequences = await db.all(Sequence, order_by=Sequence.created_at.desc())
    rows = (
        await db.session.execute(
            select(SequenceRun.sequence_id, func.count())
            .where(SequenceRun.organization_id == db.org_id)
            .group_by(SequenceRun.sequence_id)
        )
    ).all()
    counts = {sid: n for sid, n in rows}
    return {"sequences": [ser_sequence(s, runs_count=counts.get(s.id, 0)) for s in sequences]}


@router.get("/sequences/{sequence_id}")
async def get_sequence(sequence_id: str, db: TenantSession = Depends(tenant_db)):
    seq = await db.get(Sequence, sequence_id)
    if seq is None:
        raise HTTPException(status_code=404, detail="not found")
    return {"sequence": ser_sequence(seq)}


# ── Contacts ──────────────────────────────────────────────────────────────────


class ContactBody(BaseModel):
    email: str = Field(min_length=3)
    name: str | None = None
    phone: str | None = None


@router.get("/contacts")
async def list_contacts(db: TenantSession = Depends(tenant_db)):
    contacts = await db.all(Contact, order_by=Contact.created_at.desc(), limit=500)
    return {"contacts": [ser_contact(c) for c in contacts]}


@router.post("/contacts", status_code=201)
async def create_contact(body: ContactBody, db: TenantSession = Depends(tenant_db)):
    c = await db.add(Contact(email=body.email, name=body.name, phone=body.phone))
    return {"contact": ser_contact(c)}


# ── Analytics ─────────────────────────────────────────────────────────────────


@router.get("/analytics")
async def analytics(db: TenantSession = Depends(tenant_db)):
    return await compute_analytics(db.session, db.org_id)


# ── Settings ──────────────────────────────────────────────────────────────────


class SettingsBody(BaseModel):
    name: str | None = None
    settings: dict | None = None


@router.get("/settings")
async def get_settings(db: TenantSession = Depends(tenant_db)):
    org = await db.organization()
    return {"organization": ser_org(org)}


@router.patch("/settings")
async def patch_settings(
    body: SettingsBody,
    auth: AuthContext = Depends(require_user),
    db: TenantSession = Depends(tenant_db),
):
    if auth.role != "admin":
        raise HTTPException(status_code=403, detail="admin only")
    org = await db.organization()
    if org is None:
        raise HTTPException(status_code=404, detail="organization not found")
    if body.name is not None:
        org.name = body.name
    if body.settings is not None:
        org.settings = body.settings
    await db.session.flush()
    return {"organization": ser_org(org)}


# ── Event sources ─────────────────────────────────────────────────────────────


class EventSourceBody(BaseModel):
    name: str
    type: str = "generic_webhook"
    contactEmailPath: str | None = None


class EventSourcePatch(BaseModel):
    name: str | None = None
    contactEmailPath: str | None = None


@router.get("/event-sources", dependencies=[Depends(require_permission("integrations.read"))])
async def list_event_sources(db: TenantSession = Depends(tenant_db)):
    sources = await db.all(EventSource, order_by=EventSource.created_at.desc())
    return {"eventSources": [ser_event_source(s) for s in sources]}


@router.post("/event-sources", status_code=201, dependencies=[Depends(require_permission("integrations.write"))])
async def create_event_source(body: EventSourceBody, db: TenantSession = Depends(tenant_db)):
    try:
        source_type = EventSourceType(body.type)
    except ValueError as err:
        raise HTTPException(status_code=400, detail="type must be generic_webhook|sentry") from err
    kwargs = {
        "name": body.name,
        "type": source_type,
        "signing_secret": f"whsec_{secrets.token_hex(24)}",
    }
    if body.contactEmailPath:
        kwargs["contact_email_path"] = body.contactEmailPath
    s = await db.add(EventSource(**kwargs))
    return {"eventSource": ser_event_source(s)}


@router.patch("/event-sources/{source_id}", dependencies=[Depends(require_permission("integrations.write"))])
async def update_event_source(source_id: str, body: EventSourcePatch, db: TenantSession = Depends(tenant_db)):
    s = await db.get(EventSource, source_id)
    if s is None:
        raise HTTPException(status_code=404, detail="event source not found")
    if body.name is not None:
        s.name = body.name
    if body.contactEmailPath is not None:
        s.contact_email_path = body.contactEmailPath
    await db.session.flush()
    return {"eventSource": ser_event_source(s)}


@router.post("/event-sources/{source_id}/rotate-secret", dependencies=[Depends(require_permission("integrations.write"))])
async def rotate_event_source_secret(source_id: str, db: TenantSession = Depends(tenant_db)):
    s = await db.get(EventSource, source_id)
    if s is None:
        raise HTTPException(status_code=404, detail="event source not found")
    s.signing_secret = f"whsec_{secrets.token_hex(24)}"
    await db.session.flush()
    return {"eventSource": ser_event_source(s)}


@router.delete("/event-sources/{source_id}", status_code=204, dependencies=[Depends(require_permission("integrations.write"))])
async def delete_event_source(source_id: str, db: TenantSession = Depends(tenant_db)):
    s = await db.get(EventSource, source_id)
    if s is not None:
        await db.session.delete(s)


# ── API keys (plaintext shown once) ───────────────────────────────────────────


class ApiKeyBody(BaseModel):
    name: str = Field(min_length=1)


@router.get("/api-keys")
async def list_api_keys(db: TenantSession = Depends(tenant_db)):
    keys = await db.all(ApiKey, order_by=ApiKey.created_at.desc())
    return {"apiKeys": [ser_api_key(k) for k in keys]}


@router.post("/api-keys", status_code=201)
async def create_api_key(body: ApiKeyBody, db: TenantSession = Depends(tenant_db)):
    plaintext = f"dsk_{secrets.token_hex(24)}"
    k = await db.add(ApiKey(name=body.name, hashed_key=sha256_hex(plaintext)))
    return {"id": k.id, "name": k.name, "key": plaintext}
