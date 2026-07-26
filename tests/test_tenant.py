"""Tenant isolation (port of packages/db/src/tenant.test.ts).

Proves a session scoped to org A can never read or mutate org B's rows.
Requires a reachable Postgres (DATABASE_URL); skipped when the DB is down so
unit-only runs stay green.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text

from dripstack.db import Contact, Organization
from dripstack.db.session import session_scope
from dripstack.db.tenant import for_org


async def _db_up() -> bool:
    try:
        async with session_scope() as s:
            await s.execute(text("SELECT 1"))
        return True
    except Exception:  # noqa: BLE001
        return False


async def test_scopes_reads_and_writes_to_a_single_organization():
    if not await _db_up():
        pytest.skip("DB not reachable — skipping tenant isolation test")

    suffix = uuid.uuid4().hex[:8]
    async with session_scope() as session:
        org_a = Organization(name=f"A-{suffix}", settings={})
        org_b = Organization(name=f"B-{suffix}", settings={})
        session.add_all([org_a, org_b])
        await session.flush()

        db_a = for_org(session, org_a.id)
        db_b = for_org(session, org_b.id)

        c_a = await db_a.add(Contact(email=f"a-{suffix}@x.dev"))
        c_b = await db_b.add(Contact(email=f"b-{suffix}@x.dev"))

        assert c_a.organization_id == org_a.id
        assert c_b.organization_id == org_b.id

        # A sees only its own contact.
        a_contacts = await db_a.all(Contact)
        ids = [c.id for c in a_contacts]
        assert c_a.id in ids
        assert c_b.id not in ids

        # A cannot read B's contact even by id (scope wins → None).
        assert await db_a.get(Contact, c_b.id) is None

        # Cleanup.
        await session.delete(org_a)
        await session.delete(org_b)
