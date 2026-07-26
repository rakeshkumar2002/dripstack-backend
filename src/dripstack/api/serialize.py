"""Model → camelCase-JSON serializers.

The Next.js dashboard is untouched by the migration, so these emit the exact
camelCase keys + nesting that Prisma's responses produced. Datetimes are ISO
8601 with a trailing `Z` (≈ JS `Date.toISOString()`).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from ..db import (
    ActionClick,
    ApiKey,
    Contact,
    Event,
    EventSource,
    MessageLog,
    Organization,
    OutboundWebhook,
    Sequence,
    SequenceRun,
)


def iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _enum(v: Any) -> Any:
    return v.value if hasattr(v, "value") else v


def organization(o: Organization | None) -> dict[str, Any] | None:
    if o is None:
        return None
    return {
        "id": o.id,
        "name": o.name,
        "settings": o.settings or {},
        "createdAt": iso(o.created_at),
    }


def contact(c: Contact) -> dict[str, Any]:
    return {
        "id": c.id,
        "organizationId": c.organization_id,
        "email": c.email,
        "name": c.name,
        "phone": c.phone,
        "title": c.title,
        "active": c.active,
        "slackUserId": c.slack_user_id,
        "customAttributes": c.custom_attributes or {},
        "createdAt": iso(c.created_at),
    }


# ── RBAC serializers ──────────────────────────────────────────────────────────


def permission(p) -> dict[str, Any]:
    return {"id": p.id, "key": p.key, "category": _enum(p.category), "description": p.description}


def role(r) -> dict[str, Any]:
    return {
        "id": r.id,
        "name": r.name,
        "slug": r.slug,
        "scope": _enum(r.scope),
        "organizationId": r.organization_id,
        "isSystem": r.is_system,
        "permissions": sorted(p.key for p in r.permissions),
    }


def user(u, *, org_name: str | None = None) -> dict[str, Any]:
    r = u.rbac_role
    return {
        "id": u.id,
        "email": u.email,
        "organizationId": u.organization_id,
        "organizationName": org_name,
        "isPlatformStaff": u.is_platform_staff,
        "isActive": u.is_active,
        "role": {"slug": r.slug, "name": r.name, "scope": _enum(r.scope)} if r else None,
        "createdAt": iso(u.created_at),
    }


def customer(o: Organization, *, users: int = 0, technicians: int = 0, runs: int = 0) -> dict[str, Any]:
    settings = o.settings or {}
    return {
        "id": o.id,
        "name": o.name,
        "emailProvider": settings.get("emailProvider", "log"),
        "fromAddress": settings.get("fromAddress"),
        "counts": {"users": users, "technicians": technicians, "runs": runs},
        "createdAt": iso(o.created_at),
    }


def event(e: Event) -> dict[str, Any]:
    return {
        "id": e.id,
        "organizationId": e.organization_id,
        "eventSourceId": e.event_source_id,
        "type": e.type,
        "payload": e.payload,
        "contactEmail": e.contact_email,
        "payloadHash": e.payload_hash,
        "status": _enum(e.status),
        "receivedAt": iso(e.received_at),
    }


def event_source(s: EventSource) -> dict[str, Any]:
    return {
        "id": s.id,
        "organizationId": s.organization_id,
        "type": _enum(s.type),
        "name": s.name,
        "signingSecret": s.signing_secret,
        "contactEmailPath": s.contact_email_path,
        "createdAt": iso(s.created_at),
    }


def mask_url(url: str) -> str:
    """Show scheme+host and the last 4 chars; hide the secret path."""
    if not url:
        return ""
    try:
        scheme, rest = url.split("://", 1)
        host = rest.split("/", 1)[0]
        tail = url[-4:]
        return f"{scheme}://{host}/…{tail}"
    except ValueError:
        return "…" + url[-4:]


def channel_integration(ci) -> dict[str, Any]:
    return {
        "channel": ci.channel,
        "connected": True,
        "enabled": ci.enabled,
        "target": mask_url(ci.webhook_url),
        "updatedAt": iso(ci.updated_at),
    }


def sso_connection(c) -> dict[str, Any]:
    """Masked view — the client_secret is never returned."""
    return {
        "configured": True,
        "provider": c.provider,
        "issuer": c.issuer,
        "clientId": c.client_id,
        "clientSecretSet": bool(c.client_secret),
        "enabled": c.enabled,
        "autoProvision": c.auto_provision,
        "allowedDomain": c.allowed_domain,
        "defaultRoleSlug": c.default_role_slug,
        "updatedAt": iso(c.updated_at),
    }


def audit_log(a) -> dict[str, Any]:
    return {
        "id": a.id,
        "organizationId": a.organization_id,
        "actorId": a.actor_id,
        "actorLabel": a.actor_label,
        "action": a.action,
        "target": a.target,
        "meta": a.meta or {},
        "createdAt": iso(a.created_at),
    }


def outbound_webhook(w: OutboundWebhook) -> dict[str, Any]:
    return {
        "id": w.id,
        "organizationId": w.organization_id,
        "url": w.url,
        "events": list(w.events or []),
        "secret": w.secret,
        "createdAt": iso(w.created_at),
    }


def api_key(k: ApiKey) -> dict[str, Any]:
    return {
        "id": k.id,
        "name": k.name,
        "lastUsedAt": iso(k.last_used_at),
        "createdAt": iso(k.created_at),
    }


def sequence(seq: Sequence, *, runs_count: int | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": seq.id,
        "organizationId": seq.organization_id,
        "name": seq.name,
        "status": _enum(seq.status),
        "triggerRule": seq.trigger_rule,
        "steps": seq.steps,
        "version": seq.version,
        "createdAt": iso(seq.created_at),
    }
    if runs_count is not None:
        out["_count"] = {"runs": runs_count}
    return out


def message_log(m: MessageLog) -> dict[str, Any]:
    return {
        "id": m.id,
        "organizationId": m.organization_id,
        "runId": m.run_id,
        "stepId": m.step_id,
        "channel": _enum(m.channel),
        "status": _enum(m.status),
        "providerMessageId": m.provider_message_id,
        "renderedHtml": m.rendered_html,
        "renderedText": m.rendered_text,
        "error": m.error,
        "sentAt": iso(m.sent_at),
        "createdAt": iso(m.created_at),
    }


def action_click(a: ActionClick) -> dict[str, Any]:
    return {
        "id": a.id,
        "organizationId": a.organization_id,
        "runId": a.run_id,
        "action": a.action,
        "ipHash": a.ip_hash,
        "clickedAt": iso(a.clicked_at),
    }


def run_row(r: SequenceRun) -> dict[str, Any]:
    """List shape: includes sequence/contact names + message/click counts."""
    return {
        "id": r.id,
        "status": _enum(r.status),
        "currentStep": r.current_step,
        "startedAt": iso(r.started_at),
        "endedAt": iso(r.ended_at),
        "resolutionTimeSeconds": r.resolution_time_seconds,
        "sequence": {"name": r.sequence.name},
        "contact": {"email": r.contact.email, "name": r.contact.name},
        "_count": {
            "messageLogs": len(r.message_logs),
            "actionClicks": len(r.action_clicks),
        },
    }


def run_detail(r: SequenceRun) -> dict[str, Any]:
    return {
        "id": r.id,
        "status": _enum(r.status),
        "currentStep": r.current_step,
        "startedAt": iso(r.started_at),
        "endedAt": iso(r.ended_at),
        "resolutionTimeSeconds": r.resolution_time_seconds,
        "temporalWorkflowId": r.temporal_workflow_id,
        "sequence": {"name": r.sequence.name, "steps": r.sequence.steps},
        "contact": contact(r.contact),
        "event": ({"type": r.event.type, "payload": r.event.payload} if r.event else None),
        "messageLogs": [message_log(m) for m in sorted(r.message_logs, key=lambda x: x.created_at)],
        "actionClicks": [action_click(a) for a in sorted(r.action_clicks, key=lambda x: x.clicked_at)],
    }
