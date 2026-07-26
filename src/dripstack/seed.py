"""Seed the demo org + sequence (port of packages/db/prisma/seed.ts).

Creates a fresh demo organization, login user, event source, and the 3-step
"Metasys API Error Response" sequence, then writes scripts/.demo-env +
scripts/sample-event.json for the one-command demo (scripts/fire-demo-event.sh).
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from sqlalchemy import delete, select

from dripstack.config import settings
from dripstack.db import (
    Contact,
    EventSource,
    EventSourceType,
    Organization,
    OutboundWebhook,
    Permission,
    RbacRole,
    Role,
    RolePermission,
    Sequence,
    SequenceStatus,
    User,
)
from dripstack.db.session import get_engine, session_scope
from dripstack.permissions import PERMISSIONS, SYSTEM_ROLES

# Fixed so the demo curl script can sign the payload without reading the DB.
SIGNING_SECRET = "whsec_demo_secret"
DEMO_EMAIL = "demo@dripstack.dev"
DEMO_PASSWORD = "DripStackDemo!23"
INTEGRATION_EMAIL = "integration@dripstack.dev"
INTEGRATION_PASSWORD = "IntegrationDemo!23"
PLATFORM_ORG_NAME = "DripStack Platform"
TECHNICIAN_EMAIL = "cyborgrock2@gmail.com"
# Short so the timeout→escalation branch is observable quickly in the demo.
TIMEOUT_HOURS = float(os.environ.get("DEMO_TIMEOUT_HOURS", "0.05"))  # ~3 minutes

RAW_LOG = "\n".join(
    [
        "2026-06-13T09:14:02.110Z INFO  MetasysClient connecting host=nae-55.bldg7.local",
        "2026-06-13T09:14:02.224Z INFO  MetasysClient authenticated user=svc-integration",
        "2026-06-13T09:14:02.530Z DEBUG ObjectCache hydrate object=AV-2-RoomTemp-Setpoint",
        "2026-06-13T09:14:02.661Z INFO  WriteRequest target=presentValue value=72.5 priority=16",
        "2026-06-13T09:14:02.770Z DEBUG BACnetStack encode apdu=WritePropertyRequest",
        "2026-06-13T09:14:02.812Z DEBUG BACnetStack tx segments=1 invokeId=42",
        "2026-06-13T09:14:03.001Z WARN  PriorityArray slot=8 currentlyHeldBy=manualOverride",
        "2026-06-13T09:14:03.119Z ERROR WriteRequest rejected reason=OBJECT_OVERRIDDEN",
        "2026-06-13T09:14:03.120Z ERROR MetasysClient write failed object=AV-2-RoomTemp-Setpoint",
        "2026-06-13T09:14:03.121Z ERROR   status=409 code=OBJECT_OVERRIDDEN",
        '2026-06-13T09:14:03.122Z ERROR   message="Write to presentValue rejected"',
        "2026-06-13T09:14:03.123Z DEBUG   priorityArray=[null,null,null,null,null,null,null,68.0,...]",
        "2026-06-13T09:14:03.140Z INFO  Retry scheduled attempt=1 backoffMs=2000",
        "2026-06-13T09:14:05.160Z INFO  WriteRequest target=presentValue value=72.5 priority=16",
        "2026-06-13T09:14:05.290Z ERROR WriteRequest rejected reason=OBJECT_OVERRIDDEN",
        "2026-06-13T09:14:05.291Z ERROR   a higher-priority command holds this point",
        "2026-06-13T09:14:05.300Z INFO  Retry scheduled attempt=2 backoffMs=4000",
        "2026-06-13T09:14:09.330Z ERROR WriteRequest rejected reason=OBJECT_OVERRIDDEN",
        "2026-06-13T09:14:09.331Z ERROR giving up after 2 retries",
        "2026-06-13T09:14:09.340Z INFO  emitting api_error event to DripStack ingest",
    ]
)

SAMPLE_PAYLOAD = {
    "eventType": "metasys.api_error",
    "technician": {"email": TECHNICIAN_EMAIL, "name": "Alex Rivera"},
    "error": {
        "status": 409,
        "code": "OBJECT_OVERRIDDEN",
        "message": "Write to presentValue rejected",
        "object": "AV-2-RoomTemp-Setpoint",
        "details": {"site": "Building-7", "device": "NAE-55", "attemptedValue": 72.5, "priority": 16},
    },
    "rawLog": RAW_LOG,
}

STEPS = [
    {
        "id": "step-1-immediate-email",
        "order": 0,
        "channel": "email",
        "delay": {"amount": 0, "unit": "seconds"},
        "waitForAction": {"timeoutHours": TIMEOUT_HOURS, "onTimeout": "next_step"},
        "template": {
            "subject": "Metasys error {{ $.error.code }} on {{ $.error.object }}",
            "blocks": [
                {
                    "type": "text",
                    "markdown": "Hi {{ $.technician.name }},\n\nYour Metasys integration reported an error while writing to **{{ $.error.object }}** at site **{{ $.error.details.site }}**. Here's what we know and how to fix it.",
                },
                {"type": "json", "source": "event_path", "path": "$.error"},
                {"type": "ai_explanation", "inputPath": "$.error"},
                {"type": "log", "source": "event_path", "path": "$.rawLog", "collapsedLines": 12},
                {
                    "type": "actions",
                    "buttons": [
                        {"label": "Mark as resolved", "action": "resolve"},
                        {"label": "I need help", "action": "escalate"},
                    ],
                },
            ],
        },
    },
    {
        "id": "step-2-followup-email",
        "order": 1,
        "channel": "email",
        "delay": {"amount": 0, "unit": "seconds"},
        "waitForAction": {"timeoutHours": TIMEOUT_HOURS, "onTimeout": "next_step"},
        "template": {
            "subject": "Still seeing the Metasys error? We can help",
            "blocks": [
                {
                    "type": "text",
                    "markdown": "We haven't heard back, so we're checking in. If **{{ $.error.object }}** is still rejecting writes, the point is likely held at a higher priority. Tap below and we'll loop in support.",
                },
                {
                    "type": "actions",
                    "buttons": [
                        {"label": "It is resolved now", "action": "resolve"},
                        {"label": "Escalate to support", "action": "escalate"},
                    ],
                },
            ],
        },
    },
    {
        "id": "step-3-slack-escalation",
        "order": 2,
        "channel": "slack",
        "delay": {"amount": 0, "unit": "seconds"},
        "template": {
            "subject": "🚨 Unresolved Metasys incident — {{ $.error.object }}",
            "blocks": [
                {
                    "type": "text",
                    "markdown": "Escalating unresolved incident for **{{ $.technician.name }}** ({{ $.technician.email }}) at {{ $.error.details.site }}.",
                },
                {"type": "json", "source": "event_path", "path": "$.error"},
            ],
        },
    },
]


async def _seed_rbac(session) -> dict[str, RbacRole]:
    """Idempotently seed permissions + system roles + their mappings."""
    # Permissions (upsert by key).
    existing_perms = {
        p.key: p for p in (await session.execute(select(Permission))).scalars().all()
    }
    for key, category, desc in PERMISSIONS:
        p = existing_perms.get(key)
        if p is None:
            p = Permission(key=key, category=category, description=desc)
            session.add(p)
            existing_perms[key] = p
        else:
            p.category, p.description = category, desc
    await session.flush()

    roles: dict[str, RbacRole] = {}
    for slug, spec in SYSTEM_ROLES.items():
        role = (await session.execute(select(RbacRole).where(RbacRole.slug == slug))).scalars().first()
        if role is None:
            role = RbacRole(name=spec["name"], slug=slug, scope=spec["scope"], is_system=True)
            session.add(role)
            await session.flush()
        else:
            role.name, role.scope, role.is_system = spec["name"], spec["scope"], True
            await session.execute(delete(RolePermission).where(RolePermission.role_id == role.id))
        for key in spec["permissions"]:
            session.add(RolePermission(role_id=role.id, permission_id=existing_perms[key].id))
        roles[slug] = role
    await session.flush()
    return roles


async def _seed() -> str:
    from dripstack.api.auth import hash_password

    async with session_scope() as session:
        # Fresh demo orgs each run (cascades users/contacts/etc.).
        await session.execute(
            delete(Organization).where(
                Organization.name.in_(["Johnson Controls (Demo)", PLATFORM_ORG_NAME])
            )
        )
        await session.flush()

        roles = await _seed_rbac(session)

        # ── Platform org + integration-team user ──────────────────────────────
        platform_org = Organization(name=PLATFORM_ORG_NAME, settings={})
        session.add(platform_org)
        await session.flush()
        session.add(
            User(
                organization_id=platform_org.id,
                email=INTEGRATION_EMAIL,
                password_hash=hash_password(INTEGRATION_PASSWORD),
                role=Role.admin,
                role_id=roles["integration-admin"].id,
                is_platform_staff=True,
            )
        )

        org = Organization(
            name="Johnson Controls (Demo)",
            settings={
                "fromAddress": "Metasys Alerts <alerts@dripstack.dev>",
                "emailProvider": "log",
                "productDocContext": (
                    "OBJECT_OVERRIDDEN (HTTP 409): a BACnet point write was rejected because a "
                    "higher-priority entry in the priority array currently holds the point. A "
                    "technician must release the higher-priority command (often a manual override "
                    "at priority 8) before a write at priority 16 will take effect."
                ),
            },
        )
        session.add(org)
        await session.flush()

        session.add(
            User(
                organization_id=org.id,
                email=DEMO_EMAIL,
                password_hash=hash_password(DEMO_PASSWORD),
                role=Role.admin,
                role_id=roles["customer-admin"].id,
            )
        )

        # Technician the customer configures (receives the smart emails).
        session.add(
            Contact(
                organization_id=org.id,
                email=TECHNICIAN_EMAIL,
                name="Alex Rivera",
                title="Field Technician · Building-7",
                active=True,
            )
        )

        source = EventSource(
            organization_id=org.id,
            type=EventSourceType.generic_webhook,
            name="Metasys Integration",
            signing_secret=SIGNING_SECRET,
            contact_email_path="$.technician.email",
        )
        session.add(source)

        session.add(
            Sequence(
                organization_id=org.id,
                name="Metasys API Error Response",
                status=SequenceStatus.active,
                trigger_rule={
                    "eventType": "metasys.api_error",
                    "conditions": [{"path": "$.error.status", "op": "gt", "value": 400}],
                },
                steps=STEPS,
            )
        )

        outbound_url = os.environ.get("DEMO_OUTBOUND_URL")
        if outbound_url:
            session.add(
                OutboundWebhook(
                    organization_id=org.id,
                    url=outbound_url,
                    secret="whsec_outbound_demo",
                    events=["run.escalated", "run.resolved", "run.completed"],
                )
            )

        await session.flush()
        source_id = source.id

    return source_id


def _demo_dir() -> Path:
    """Where the demo files land. Overridable for containers, where scripts/ is
    excluded from the image."""
    override = os.environ.get("DRIPSTACK_DEMO_DIR")
    if override:
        return Path(override)
    # seed.py lives at <root>/src/dripstack/seed.py → the repo root is 2 up,
    # with scripts/ beside src/.
    return Path(__file__).resolve().parents[2] / "scripts"


def _write_demo_files(source_id: str) -> None:
    # These files embed the demo signing secret; never write them in production.
    if settings().is_production:
        print("  (production: skipping demo file write)")
        return
    demo_dir = _demo_dir()
    ingest_base = settings().APP_BASE_URL or "http://localhost:4000"
    try:
        demo_dir.mkdir(parents=True, exist_ok=True)
        (demo_dir / ".demo-env").write_text(
            f"EVENT_SOURCE_ID={source_id}\nSIGNING_SECRET={SIGNING_SECRET}\nINGEST_BASE={ingest_base}\n"
        )
        (demo_dir / "sample-event.json").write_text(json.dumps(SAMPLE_PAYLOAD, indent=2))
    except OSError as err:
        print(f"⚠  could not write demo files to {demo_dir}: {err}")
        return
    # Echo the resolved path — mkdir(parents=True) means a wrong directory would
    # otherwise be created silently rather than raising.
    print(f"  demo files written to {demo_dir}")


async def _amain() -> None:
    source_id = await _seed()
    _write_demo_files(source_id)
    await get_engine().dispose()

    print("\n✅ Seed complete\n")
    print("  Integration team login (platform · manages all customers):")
    print(f"    email:    {INTEGRATION_EMAIL}")
    print(f"    password: {INTEGRATION_PASSWORD}")
    print("\n  Customer admin login (manages own technicians + settings):")
    print(f"    email:    {DEMO_EMAIL}")
    print(f"    password: {DEMO_PASSWORD}")
    print(f"\n  Technician (configured, receives emails): {TECHNICIAN_EMAIL}")
    print(f"\n  Event source id: {source_id}")
    print(f"  Signing secret:  {SIGNING_SECRET}")
    print(f"  waitForAction timeout: {TIMEOUT_HOURS}h (set DEMO_TIMEOUT_HOURS to change)\n")
    print("  Run the demo:  ./scripts/fire-demo-event.sh")
    print("  Then open:     http://localhost:4000/dev/emails\n")


def main() -> None:
    asyncio.run(_amain())


if __name__ == "__main__":
    main()
