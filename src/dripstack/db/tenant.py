"""Tenant scoping (reimplements packages/db/src/tenant.ts `forOrg`).

`for_org(session, organization_id)` returns a `TenantSession`: a thin wrapper
whose read/write helpers ALWAYS inject `organization_id`, so a route handler
physically cannot read or write across organizations. This is enforcement, not
convenience — the scope is applied inside the helper and a caller can't bypass
it without reaching for the raw session.

`Organization` is the tenant root, scoped by `id` instead of `organization_id`.
"""

from __future__ import annotations

from typing import TypeVar

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Base, Organization

T = TypeVar("T", bound=Base)


class TenantSession:
    def __init__(self, session: AsyncSession, organization_id: str) -> None:
        self.session = session
        self.org_id = organization_id

    def _scope(self, model: type[T]):
        if model is Organization:
            return Organization.id == self.org_id
        return model.organization_id == self.org_id  # type: ignore[attr-defined]

    async def all(
        self,
        model: type[T],
        *criteria,
        order_by=None,
        limit: int | None = None,
    ) -> list[T]:
        stmt = select(model).where(self._scope(model), *criteria)
        if order_by is not None:
            stmt = stmt.order_by(order_by)
        if limit is not None:
            stmt = stmt.limit(limit)
        res = await self.session.execute(stmt)
        return list(res.scalars().all())

    async def first(self, model: type[T], *criteria) -> T | None:
        stmt = select(model).where(self._scope(model), *criteria).limit(1)
        res = await self.session.execute(stmt)
        return res.scalars().first()

    async def get(self, model: type[T], id_: str) -> T | None:
        return await self.first(model, model.id == id_)  # type: ignore[attr-defined]

    async def organization(self) -> Organization | None:
        return await self.first(Organization)

    def stamp(self, instance: T) -> T:
        """Force organization_id on a new instance before it is persisted."""
        if not isinstance(instance, Organization):
            instance.organization_id = self.org_id  # type: ignore[attr-defined]
        return instance

    async def add(self, instance: T, *, flush: bool = True) -> T:
        self.stamp(instance)
        self.session.add(instance)
        if flush:
            await self.session.flush()
        return instance

    async def commit(self) -> None:
        await self.session.commit()


def for_org(session: AsyncSession, organization_id: str) -> TenantSession:
    return TenantSession(session, organization_id)
