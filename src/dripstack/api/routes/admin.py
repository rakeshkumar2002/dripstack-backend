"""Org-scoped admin endpoints (customer admins): users, technicians, email config.

All tenant-scoped via `tenant_db`, each gated by an RBAC permission.
"""

from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import select

from ...config import settings
from ...db import (
    AuditLog,
    ChannelIntegration,
    Contact,
    OutboundWebhook,
    RbacRole,
    Role,
    Sequence,
    SequenceStatus,
    User,
)
from ...db.tenant import TenantSession
from ...providers.channels import get_channel_sender
from ...shared.types import parse_steps, parse_trigger
from ..audit import record_audit
from ..auth import Principal, current_principal, hash_password, require_permission, tenant_db
from ..serialize import audit_log as ser_audit
from ..serialize import channel_integration as ser_channel
from ..serialize import contact as ser_contact
from ..serialize import outbound_webhook as ser_outbound_webhook
from ..serialize import sequence as ser_sequence
from ..serialize import user as ser_user

router = APIRouter(prefix="/api/v1")

ORG_ROLES = {"customer-admin", "customer-member"}


# ── Org users / team ──────────────────────────────────────────────────────────


class OrgUserBody(BaseModel):
    email: str = Field(min_length=3)
    password: str = Field(min_length=8)
    roleSlug: str = "customer-member"


class OrgUserPatch(BaseModel):
    roleSlug: str | None = None
    password: str | None = None
    isActive: bool | None = None


async def _org_role(db: TenantSession, slug: str) -> RbacRole:
    if slug not in ORG_ROLES:
        raise HTTPException(status_code=400, detail="role must be a customer role")
    role = (await db.session.execute(select(RbacRole).where(RbacRole.slug == slug))).scalars().first()
    if role is None:
        raise HTTPException(status_code=400, detail=f"unknown role: {slug}")
    return role


def _is_active_admin(u: User) -> bool:
    return bool(u.is_active) and u.rbac_role is not None and u.rbac_role.slug == "customer-admin"


async def _assert_keeps_an_admin(db: TenantSession, target: User) -> None:
    """Block a change that would remove the org's last active customer-admin."""
    users = await db.all(User)
    remaining = sum(1 for u in users if u.id != target.id and _is_active_admin(u))
    if remaining == 0:
        raise HTTPException(status_code=400, detail="organization must keep at least one admin")


@router.get("/users", dependencies=[Depends(require_permission("users.read"))])
async def list_users(db: TenantSession = Depends(tenant_db)):
    users = await db.all(User, order_by=User.created_at.desc())
    return {"users": [ser_user(u) for u in users]}


@router.post("/users", status_code=201)
async def create_user(
    body: OrgUserBody,
    request: Request,
    db: TenantSession = Depends(tenant_db),
    principal: Principal = Depends(require_permission("users.write")),
):
    dupe = await db.first(User, User.email == body.email)
    if dupe is not None:
        raise HTTPException(status_code=409, detail="email already registered in this org")
    role = await _org_role(db, body.roleSlug)
    u = await db.add(
        User(
            email=body.email,
            password_hash=hash_password(body.password),
            role=Role.admin if role.slug == "customer-admin" else Role.member,
            role_id=role.id,
        )
    )
    await db.session.refresh(u)
    await record_audit(
        organization_id=db.org_id,
        action="user.create",
        actor_id=principal.user_id,
        target=u.id,
        meta={"email": u.email, "role": role.slug},
        request=request,
    )
    return {"user": ser_user(u)}


@router.patch("/users/{user_id}", dependencies=[Depends(require_permission("users.write"))])
async def update_user(
    user_id: str,
    body: OrgUserPatch,
    db: TenantSession = Depends(tenant_db),
    principal: Principal = Depends(current_principal),
):
    u = await db.get(User, user_id)
    if u is None:
        raise HTTPException(status_code=404, detail="user not found")
    # Demoting or disabling an admin must not lock the org out.
    demotes = bool(body.roleSlug) and body.roleSlug != "customer-admin"
    disables = body.isActive is False
    if _is_active_admin(u) and (demotes or disables):
        if u.id == principal.user_id:
            raise HTTPException(status_code=400, detail="you cannot remove your own admin access")
        await _assert_keeps_an_admin(db, u)
    if body.roleSlug:
        role = await _org_role(db, body.roleSlug)
        u.role_id = role.id
    if body.password:
        u.password_hash = hash_password(body.password)
    if body.isActive is not None:
        u.is_active = body.isActive
    await db.session.flush()
    await db.session.refresh(u)
    await record_audit(
        organization_id=db.org_id,
        action="user.update",
        actor_id=principal.user_id,
        target=u.id,
        meta={
            "email": u.email,
            "roleChanged": bool(body.roleSlug),
            "passwordChanged": bool(body.password),
            "isActive": body.isActive,
        },
    )
    return {"user": ser_user(u)}


@router.delete("/users/{user_id}", status_code=204, dependencies=[Depends(require_permission("users.delete"))])
async def delete_user(
    user_id: str,
    db: TenantSession = Depends(tenant_db),
    principal: Principal = Depends(current_principal),
):
    u = await db.get(User, user_id)
    if u is None:
        return
    if u.id == principal.user_id:
        raise HTTPException(status_code=400, detail="you cannot delete your own account")
    if _is_active_admin(u):
        await _assert_keeps_an_admin(db, u)
    deleted_email = u.email
    await db.session.delete(u)
    await record_audit(
        organization_id=db.org_id,
        action="user.delete",
        actor_id=principal.user_id,
        target=user_id,
        meta={"email": deleted_email},
    )


# ── Audit log (read-only security trail) ──────────────────────────────────────


@router.get("/audit-logs", dependencies=[Depends(require_permission("users.read"))])
async def list_audit_logs(limit: int = 100, db: TenantSession = Depends(tenant_db)):
    limit = max(1, min(limit, 500))
    rows = await db.all(AuditLog, order_by=AuditLog.created_at.desc(), limit=limit)
    return {"auditLogs": [ser_audit(a) for a in rows]}


# ── Technicians (Contact) ─────────────────────────────────────────────────────


class TechnicianBody(BaseModel):
    email: str = Field(min_length=3)
    name: str | None = None
    title: str | None = None
    phone: str | None = None


class TechnicianPatch(BaseModel):
    email: str | None = None
    name: str | None = None
    title: str | None = None
    phone: str | None = None
    active: bool | None = None


@router.get("/technicians", dependencies=[Depends(require_permission("technicians.read"))])
async def list_technicians(db: TenantSession = Depends(tenant_db)):
    techs = await db.all(Contact, order_by=Contact.created_at.desc(), limit=500)
    return {"technicians": [ser_contact(c) for c in techs]}


@router.post("/technicians", status_code=201, dependencies=[Depends(require_permission("technicians.write"))])
async def create_technician(body: TechnicianBody, db: TenantSession = Depends(tenant_db)):
    dupe = await db.first(Contact, Contact.email == body.email)
    if dupe is not None:
        raise HTTPException(status_code=409, detail="technician with that email already exists")
    c = await db.add(Contact(email=body.email, name=body.name, title=body.title, phone=body.phone))
    return {"technician": ser_contact(c)}


@router.patch("/technicians/{tech_id}", dependencies=[Depends(require_permission("technicians.write"))])
async def update_technician(tech_id: str, body: TechnicianPatch, db: TenantSession = Depends(tenant_db)):
    c = await db.get(Contact, tech_id)
    if c is None:
        raise HTTPException(status_code=404, detail="technician not found")
    for fld in ("email", "name", "title", "phone", "active"):
        val = getattr(body, fld)
        if val is not None:
            setattr(c, fld, val)
    await db.session.flush()
    return {"technician": ser_contact(c)}


@router.delete("/technicians/{tech_id}", status_code=204, dependencies=[Depends(require_permission("technicians.write"))])
async def delete_technician(tech_id: str, db: TenantSession = Depends(tenant_db)):
    c = await db.get(Contact, tech_id)
    if c is not None:
        await db.session.delete(c)


# ── Email / ESP settings ──────────────────────────────────────────────────────


class EmailSettingsPatch(BaseModel):
    emailProvider: str | None = None  # log | resend | ses
    fromAddress: str | None = None
    defaultTechnicianEmail: str | None = None


def _live_delivery(provider: str) -> bool:
    if provider == "resend":
        return bool(settings().RESEND_API_KEY)
    if provider == "ses":
        return True  # credentials resolved from the boto3 chain / IAM role
    return False  # log = preview only


@router.get("/email-settings", dependencies=[Depends(require_permission("technicians.read"))])
async def get_email_settings(db: TenantSession = Depends(tenant_db)):
    org = await db.organization()
    s = (org.settings if org else {}) or {}
    provider = s.get("emailProvider", "log")
    return {
        "emailProvider": provider,
        "fromAddress": s.get("fromAddress") or settings().EMAIL_FROM_DEFAULT,
        "defaultTechnicianEmail": s.get("defaultTechnicianEmail"),
        "liveDelivery": _live_delivery(provider),
    }


@router.patch("/email-settings", dependencies=[Depends(require_permission("email.write"))])
async def update_email_settings(body: EmailSettingsPatch, db: TenantSession = Depends(tenant_db)):
    org = await db.organization()
    if org is None:
        raise HTTPException(status_code=404, detail="organization not found")
    s = dict(org.settings or {})
    if body.emailProvider is not None:
        if body.emailProvider not in ("log", "resend", "ses"):
            raise HTTPException(status_code=400, detail="invalid provider")
        s["emailProvider"] = body.emailProvider
    if body.fromAddress is not None:
        s["fromAddress"] = body.fromAddress
    if body.defaultTechnicianEmail is not None:
        s["defaultTechnicianEmail"] = body.defaultTechnicianEmail
    org.settings = s
    await db.session.flush()
    provider = s.get("emailProvider", "log")
    return {
        "emailProvider": provider,
        "fromAddress": s.get("fromAddress"),
        "defaultTechnicianEmail": s.get("defaultTechnicianEmail"),
        "liveDelivery": _live_delivery(provider),
    }


# ── Sequences (drip recipes) ──────────────────────────────────────────────────


class SequenceBody(BaseModel):
    name: str = Field(min_length=1)
    status: str = "draft"
    triggerRule: dict
    steps: list[dict]


class SequencePatch(BaseModel):
    name: str | None = None
    status: str | None = None
    triggerRule: dict | None = None
    steps: list[dict] | None = None


def _validate_status(status: str) -> SequenceStatus:
    try:
        return SequenceStatus(status)
    except ValueError as err:
        raise HTTPException(status_code=400, detail="status must be draft|active|paused") from err


def _validate_trigger(rule: dict) -> None:
    try:
        parse_trigger(rule)
    except ValidationError as err:
        raise HTTPException(status_code=400, detail=f"invalid trigger: {err.errors()[:3]}") from err


def _validate_steps(steps: list[dict]) -> None:
    try:
        parse_steps(steps)
    except ValidationError as err:
        raise HTTPException(status_code=400, detail=f"invalid steps: {err.errors()[:3]}") from err


@router.post("/sequences", status_code=201, dependencies=[Depends(require_permission("sequences.write"))])
async def create_sequence(body: SequenceBody, db: TenantSession = Depends(tenant_db)):
    status = _validate_status(body.status)
    _validate_trigger(body.triggerRule)
    _validate_steps(body.steps)
    seq = await db.add(
        Sequence(name=body.name, status=status, trigger_rule=body.triggerRule, steps=body.steps)
    )
    return {"sequence": ser_sequence(seq)}


@router.patch("/sequences/{sequence_id}", dependencies=[Depends(require_permission("sequences.write"))])
async def update_sequence(sequence_id: str, body: SequencePatch, db: TenantSession = Depends(tenant_db)):
    seq = await db.get(Sequence, sequence_id)
    if seq is None:
        raise HTTPException(status_code=404, detail="sequence not found")
    if body.name is not None:
        seq.name = body.name
    if body.status is not None:
        seq.status = _validate_status(body.status)
    if body.triggerRule is not None:
        _validate_trigger(body.triggerRule)
        seq.trigger_rule = body.triggerRule
    if body.steps is not None:
        _validate_steps(body.steps)
        seq.steps = body.steps
        seq.version = (seq.version or 1) + 1  # new step content = new version
    await db.session.flush()
    return {"sequence": ser_sequence(seq)}


@router.delete("/sequences/{sequence_id}", status_code=204, dependencies=[Depends(require_permission("sequences.write"))])
async def delete_sequence(sequence_id: str, db: TenantSession = Depends(tenant_db)):
    seq = await db.get(Sequence, sequence_id)
    if seq is not None:
        await db.session.delete(seq)


# ── Outbound webhooks (generic delivery channel) ──────────────────────────────

# Run lifecycle events the worker can deliver (worker/activities.py emits run.{status}).
OUTBOUND_EVENTS = {"run.resolved", "run.escalated", "run.completed", "run.failed"}


class OutboundWebhookBody(BaseModel):
    url: str = Field(min_length=1)
    events: list[str]


class OutboundWebhookPatch(BaseModel):
    url: str | None = None
    events: list[str] | None = None


def _validate_events(events: list[str]) -> None:
    invalid = [e for e in events if e not in OUTBOUND_EVENTS]
    if not events or invalid:
        raise HTTPException(
            status_code=400,
            detail=f"events must be a non-empty subset of {sorted(OUTBOUND_EVENTS)}",
        )


@router.get("/outbound-webhooks", dependencies=[Depends(require_permission("integrations.read"))])
async def list_outbound_webhooks(db: TenantSession = Depends(tenant_db)):
    hooks = await db.all(OutboundWebhook, order_by=OutboundWebhook.created_at.desc())
    return {"outboundWebhooks": [ser_outbound_webhook(h) for h in hooks]}


@router.post("/outbound-webhooks", status_code=201, dependencies=[Depends(require_permission("integrations.write"))])
async def create_outbound_webhook(body: OutboundWebhookBody, db: TenantSession = Depends(tenant_db)):
    _validate_events(body.events)
    h = await db.add(
        OutboundWebhook(url=body.url, events=body.events, secret=f"whsec_{secrets.token_hex(24)}")
    )
    return {"outboundWebhook": ser_outbound_webhook(h)}


@router.patch("/outbound-webhooks/{hook_id}", dependencies=[Depends(require_permission("integrations.write"))])
async def update_outbound_webhook(hook_id: str, body: OutboundWebhookPatch, db: TenantSession = Depends(tenant_db)):
    h = await db.get(OutboundWebhook, hook_id)
    if h is None:
        raise HTTPException(status_code=404, detail="webhook not found")
    if body.url is not None:
        h.url = body.url
    if body.events is not None:
        _validate_events(body.events)
        h.events = body.events
    await db.session.flush()
    return {"outboundWebhook": ser_outbound_webhook(h)}


@router.delete("/outbound-webhooks/{hook_id}", status_code=204, dependencies=[Depends(require_permission("integrations.write"))])
async def delete_outbound_webhook(hook_id: str, db: TenantSession = Depends(tenant_db)):
    h = await db.get(OutboundWebhook, hook_id)
    if h is not None:
        await db.session.delete(h)


# ── Native channels (Slack / Teams incoming webhooks) ─────────────────────────

CHANNELS = ("slack", "teams")


class ChannelBody(BaseModel):
    webhookUrl: str = Field(min_length=1)
    enabled: bool = True


def _check_channel(channel: str) -> None:
    if channel not in CHANNELS:
        raise HTTPException(status_code=400, detail=f"channel must be one of {list(CHANNELS)}")


async def _get_channel(db: TenantSession, channel: str) -> ChannelIntegration | None:
    return await db.first(ChannelIntegration, ChannelIntegration.channel == channel)


@router.get("/channels", dependencies=[Depends(require_permission("integrations.read"))])
async def list_channels(db: TenantSession = Depends(tenant_db)):
    rows = {c.channel: c for c in await db.all(ChannelIntegration)}
    out = []
    for ch in CHANNELS:
        ci = rows.get(ch)
        out.append(ser_channel(ci) if ci else {"channel": ch, "connected": False, "enabled": False, "target": None})
    return {"channels": out}


@router.put("/channels/{channel}", dependencies=[Depends(require_permission("integrations.write"))])
async def upsert_channel(channel: str, body: ChannelBody, db: TenantSession = Depends(tenant_db)):
    _check_channel(channel)
    if not body.webhookUrl.startswith("https://"):
        raise HTTPException(status_code=400, detail="webhook URL must be an https:// URL")
    ci = await _get_channel(db, channel)
    if ci is None:
        ci = await db.add(ChannelIntegration(channel=channel, webhook_url=body.webhookUrl, enabled=body.enabled))
    else:
        ci.webhook_url = body.webhookUrl
        ci.enabled = body.enabled
        await db.session.flush()
    return {"channel": ser_channel(ci)}


@router.delete("/channels/{channel}", status_code=204, dependencies=[Depends(require_permission("integrations.write"))])
async def delete_channel(channel: str, db: TenantSession = Depends(tenant_db)):
    _check_channel(channel)
    ci = await _get_channel(db, channel)
    if ci is not None:
        await db.session.delete(ci)


@router.post("/channels/{channel}/test", dependencies=[Depends(require_permission("integrations.write"))])
async def test_channel(channel: str, db: TenantSession = Depends(tenant_db)):
    _check_channel(channel)
    ci = await _get_channel(db, channel)
    if ci is None:
        raise HTTPException(status_code=404, detail="channel not connected")
    sender = get_channel_sender(channel, ci)
    try:
        await sender.send(
            to="test",
            subject="DripStack test message",
            html="",
            text="✅ This is a test from DripStack — your channel is wired up correctly.",
            link=f"{settings().DASHBOARD_URL}/integrations",
        )
        return {"ok": True, "detail": f"Test message posted to {channel}."}
    except Exception as err:  # noqa: BLE001 - report delivery failure to the UI
        return {"ok": False, "detail": str(err)}
