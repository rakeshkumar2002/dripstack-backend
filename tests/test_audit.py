"""Audit trail: logins are recorded, the audit-logs endpoint returns them, and
members (lacking users.read) are denied."""

from __future__ import annotations

import uuid

import httpx
import pytest
from httpx import ASGITransport
from sqlalchemy import text

from dripstack.db.session import session_scope


async def _db_up() -> bool:
    try:
        async with session_scope() as s:
            await s.execute(text("SELECT 1"))
        return True
    except Exception:  # noqa: BLE001
        return False


def _app():
    from dripstack.api.main import create_app

    return create_app()


async def test_login_is_audited_and_listed():
    if not await _db_up():
        pytest.skip("DB not reachable")
    async with httpx.AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
        tok = (
            await c.post("/api/v1/auth/login", json={"email": "demo@dripstack.dev", "password": "DripStackDemo!23"})
        ).json()["accessToken"]
        admin = {"authorization": f"Bearer {tok}"}

        logs = (await c.get("/api/v1/audit-logs", headers=admin)).json()["auditLogs"]
        assert any(le["action"] == "auth.login" and le["actorLabel"] == "demo@dripstack.dev" for le in logs)


async def test_failed_login_is_audited():
    if not await _db_up():
        pytest.skip("DB not reachable")
    async with httpx.AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
        await c.post("/api/v1/auth/login", json={"email": "demo@dripstack.dev", "password": "WRONG"})
        tok = (
            await c.post("/api/v1/auth/login", json={"email": "demo@dripstack.dev", "password": "DripStackDemo!23"})
        ).json()["accessToken"]
        admin = {"authorization": f"Bearer {tok}"}
        logs = (await c.get("/api/v1/audit-logs", headers=admin)).json()["auditLogs"]
        assert any(le["action"] == "auth.login_failed" for le in logs)


async def test_member_cannot_read_audit_logs():
    if not await _db_up():
        pytest.skip("DB not reachable")
    async with httpx.AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
        tok = (
            await c.post("/api/v1/auth/login", json={"email": "demo@dripstack.dev", "password": "DripStackDemo!23"})
        ).json()["accessToken"]
        admin = {"authorization": f"Bearer {tok}"}

        email = f"member-{uuid.uuid4().hex[:6]}@x.dev"
        await c.post(
            "/api/v1/users", headers=admin,
            json={"email": email, "password": "abcd1234", "roleSlug": "customer-member"},
        )
        mtok = (await c.post("/api/v1/auth/login", json={"email": email, "password": "abcd1234"})).json()["accessToken"]
        member = {"authorization": f"Bearer {mtok}"}
        assert (await c.get("/api/v1/audit-logs", headers=member)).status_code == 403

        # Cleanup.
        for u in (await c.get("/api/v1/users", headers=admin)).json()["users"]:
            if u["email"] == email:
                await c.delete(f"/api/v1/users/{u['id']}", headers=admin)
