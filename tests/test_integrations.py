"""Integrations: outbound-webhook validation + event-source/webhook RBAC.

Pure-unit covers event validation; an in-process app test (skipped when DB is
down) covers the create-returns-secret flow and the integrations.write 403 path.
"""

from __future__ import annotations

import uuid

import httpx
import pytest
from fastapi import HTTPException
from httpx import ASGITransport
from sqlalchemy import text

from dripstack.api.routes.admin import _validate_events
from dripstack.db.session import session_scope

# ── Pure unit ─────────────────────────────────────────────────────────────────


def test_validate_events_accepts_known_subset():
    _validate_events(["run.resolved", "run.escalated"])  # no raise


def test_validate_events_rejects_empty():
    with pytest.raises(HTTPException) as exc:
        _validate_events([])
    assert exc.value.status_code == 400


def test_validate_events_rejects_unknown():
    with pytest.raises(HTTPException) as exc:
        _validate_events(["run.exploded"])
    assert exc.value.status_code == 400


# ── In-process app (skippable) ────────────────────────────────────────────────


async def _db_up() -> bool:
    try:
        async with session_scope() as s:
            await s.execute(text("SELECT 1"))
        return True
    except Exception:  # noqa: BLE001
        return False


async def test_integration_endpoints_and_member_403():
    if not await _db_up():
        pytest.skip("DB not reachable — skipping integrations app test")

    from dripstack.api.main import create_app

    async with httpx.AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:
        tok = (
            await c.post("/api/v1/auth/login", json={"email": "demo@dripstack.dev", "password": "DripStackDemo!23"})
        ).json()["accessToken"]
        admin = {"authorization": f"Bearer {tok}"}

        # Event source create returns a signing secret.
        es = await c.post("/api/v1/event-sources", headers=admin, json={"name": f"src-{uuid.uuid4().hex[:6]}"})
        assert es.status_code == 201
        src = es.json()["eventSource"]
        assert src["signingSecret"].startswith("whsec_")

        # Outbound webhook create returns a secret; bad events → 400.
        bad = await c.post("/api/v1/outbound-webhooks", headers=admin, json={"url": "https://x.dev/h", "events": ["nope"]})
        assert bad.status_code == 400
        wh = await c.post("/api/v1/outbound-webhooks", headers=admin, json={"url": "https://x.dev/h", "events": ["run.resolved"]})
        assert wh.status_code == 201
        hook = wh.json()["outboundWebhook"]
        assert hook["secret"].startswith("whsec_")

        # A customer-member is read-only on integrations.write.
        email = f"member-{uuid.uuid4().hex[:6]}@x.dev"
        await c.post("/api/v1/users", headers=admin, json={"email": email, "password": "abcd1234", "roleSlug": "customer-member"})
        mtok = (
            await c.post("/api/v1/auth/login", json={"email": email, "password": "abcd1234"})
        ).json()["accessToken"]
        member = {"authorization": f"Bearer {mtok}"}
        assert (await c.get("/api/v1/outbound-webhooks", headers=member)).status_code == 200
        assert (await c.post("/api/v1/outbound-webhooks", headers=member, json={"url": "https://x.dev/h", "events": ["run.resolved"]})).status_code == 403
        assert (await c.post("/api/v1/event-sources", headers=member, json={"name": "x"})).status_code == 403

        # Cleanup.
        await c.delete(f"/api/v1/outbound-webhooks/{hook['id']}", headers=admin)
        await c.delete(f"/api/v1/event-sources/{src['id']}", headers=admin)
        me = (await c.get("/api/v1/users", headers=admin)).json()["users"]
        for u in me:
            if u["email"] == email:
                await c.delete(f"/api/v1/users/{u['id']}", headers=admin)
