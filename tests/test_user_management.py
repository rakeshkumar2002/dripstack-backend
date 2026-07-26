"""User-management hardening: privilege-escalation, last-admin & disabled guards.

Pure-unit tests cover the role-assignment guard and the active-admin predicate;
the last-admin guard is exercised against a real DB (skipped when DB is down).
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import text

from dripstack.api.routes.admin import _assert_keeps_an_admin, _is_active_admin, _org_role
from dripstack.db import RbacRole, RoleScope, User
from dripstack.db.session import session_scope
from dripstack.db.tenant import for_org

# ── Pure unit ─────────────────────────────────────────────────────────────────


async def test_org_role_rejects_platform_role():
    """A customer admin must never be able to assign a platform role."""
    with pytest.raises(HTTPException) as exc:
        await _org_role(db=None, slug="integration-admin")
    assert exc.value.status_code == 400
    assert "customer role" in exc.value.detail


async def test_org_role_rejects_unknown_role():
    with pytest.raises(HTTPException) as exc:
        await _org_role(db=None, slug="root")
    assert exc.value.status_code == 400


def test_is_active_admin_predicate():
    admin = SimpleNamespace(is_active=True, rbac_role=SimpleNamespace(slug="customer-admin"))
    member = SimpleNamespace(is_active=True, rbac_role=SimpleNamespace(slug="customer-member"))
    disabled = SimpleNamespace(is_active=False, rbac_role=SimpleNamespace(slug="customer-admin"))
    none = SimpleNamespace(is_active=True, rbac_role=None)
    assert _is_active_admin(admin) is True
    assert _is_active_admin(member) is False
    assert _is_active_admin(disabled) is False
    assert _is_active_admin(none) is False


# ── DB-backed (skippable) ─────────────────────────────────────────────────────


async def _db_up() -> bool:
    try:
        async with session_scope() as s:
            await s.execute(text("SELECT 1"))
        return True
    except Exception:  # noqa: BLE001
        return False


async def test_last_admin_guard_blocks_removing_final_admin():
    if not await _db_up():
        pytest.skip("DB not reachable — skipping last-admin guard test")

    from sqlalchemy import select

    from dripstack.db import Organization

    suffix = uuid.uuid4().hex[:8]
    async with session_scope() as session:
        # Use the canonical customer-admin role (the slug the predicate checks);
        # create it only if this DB hasn't been seeded.
        role = (
            await session.execute(select(RbacRole).where(RbacRole.slug == "customer-admin"))
        ).scalars().first()
        created_role = role is None
        if created_role:
            role = RbacRole(name="Customer Admin", slug="customer-admin", scope=RoleScope.organization)
            session.add(role)
            await session.flush()

        org = Organization(name=f"guard-{suffix}", settings={})
        session.add(org)
        await session.flush()

        db = for_org(session, org.id)
        a1 = await db.add(User(email=f"a1-{suffix}@x.dev", password_hash="x", role_id=role.id))
        a2 = await db.add(User(email=f"a2-{suffix}@x.dev", password_hash="x", role_id=role.id))
        await session.refresh(a1)
        await session.refresh(a2)

        # Two active admins (scoped to this org) → removing one is fine.
        await _assert_keeps_an_admin(db, a1)

        # Disable a2 → a1 is now the only admin → removing it must fail.
        a2.is_active = False
        await session.flush()
        with pytest.raises(HTTPException) as exc:
            await _assert_keeps_an_admin(db, a1)
        assert exc.value.status_code == 400

        await session.delete(org)
        if created_role:
            await session.delete(role)
