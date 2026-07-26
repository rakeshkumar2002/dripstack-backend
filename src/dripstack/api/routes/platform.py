"""Platform (integration-team) endpoints — cross-org, gated by `require_platform`.

These intentionally bypass tenant scoping (they manage ALL customers), so they
use the raw session + explicit permission checks rather than `tenant_db`.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...db import Contact, Organization, RbacRole, Role, SequenceRun, User
from ..auth import (
    Principal,
    current_principal,
    get_session,
    hash_password,
    require_permission,
    require_platform,
)
from ..serialize import customer as ser_customer
from ..serialize import role as ser_role
from ..serialize import user as ser_user

router = APIRouter(prefix="/api/v1/platform", dependencies=[Depends(require_platform)])


class CustomerBody(BaseModel):
    name: str = Field(min_length=1)
    adminEmail: str = Field(min_length=3)
    adminPassword: str = Field(min_length=8)


class CustomerPatch(BaseModel):
    name: str | None = None
    settings: dict | None = None


class PlatformUserBody(BaseModel):
    organizationId: str
    email: str = Field(min_length=3)
    password: str = Field(min_length=8)
    roleSlug: str


class PlatformUserPatch(BaseModel):
    roleSlug: str | None = None
    password: str | None = None
    isActive: bool | None = None


async def _role(session: AsyncSession, slug: str) -> RbacRole:
    role = (await session.execute(select(RbacRole).where(RbacRole.slug == slug))).scalars().first()
    if role is None:
        raise HTTPException(status_code=400, detail=f"unknown role: {slug}")
    return role


def _is_active_platform_admin(u: User) -> bool:
    return bool(u.is_active) and u.rbac_role is not None and u.rbac_role.slug == "integration-admin"


async def _assert_keeps_a_platform_admin(session: AsyncSession, target: User) -> None:
    """Block removing/demoting the last active integration-admin (platform lockout)."""
    users = (await session.execute(select(User))).scalars().all()
    remaining = sum(1 for u in users if u.id != target.id and _is_active_platform_admin(u))
    if remaining == 0:
        raise HTTPException(status_code=400, detail="platform must keep at least one integration admin")


async def _counts(session: AsyncSession, column) -> dict[str, int]:
    rows = (await session.execute(select(column, func.count()).group_by(column))).all()
    return {oid: n for oid, n in rows}


# ── Customers (organizations) ─────────────────────────────────────────────────


@router.get("/customers", dependencies=[Depends(require_permission("customers.read"))])
async def list_customers(session: AsyncSession = Depends(get_session)):
    orgs = (await session.execute(select(Organization).order_by(Organization.created_at.desc()))).scalars().all()
    users = await _counts(session, User.organization_id)
    techs = await _counts(session, Contact.organization_id)
    runs = await _counts(session, SequenceRun.organization_id)
    return {
        "customers": [
            ser_customer(o, users=users.get(o.id, 0), technicians=techs.get(o.id, 0), runs=runs.get(o.id, 0))
            for o in orgs
        ]
    }


@router.post("/customers", status_code=201, dependencies=[Depends(require_permission("customers.write"))])
async def create_customer(body: CustomerBody, session: AsyncSession = Depends(get_session)):
    dupe = (await session.execute(select(User).where(User.email == body.adminEmail))).scalars().first()
    if dupe is not None:
        raise HTTPException(status_code=409, detail="admin email already registered")
    org = Organization(name=body.name, settings={"emailProvider": "log"})
    session.add(org)
    await session.flush()
    role = await _role(session, "customer-admin")
    admin = User(
        organization_id=org.id,
        email=body.adminEmail,
        password_hash=hash_password(body.adminPassword),
        role=Role.admin,
        role_id=role.id,
    )
    session.add(admin)
    await session.flush()
    return {"customer": ser_customer(org, users=1)}


@router.patch("/customers/{org_id}", dependencies=[Depends(require_permission("customers.write"))])
async def update_customer(org_id: str, body: CustomerPatch, session: AsyncSession = Depends(get_session)):
    org = await session.get(Organization, org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="customer not found")
    if body.name is not None:
        org.name = body.name
    if body.settings is not None:
        org.settings = {**(org.settings or {}), **body.settings}
    await session.flush()
    return {"customer": ser_customer(org)}


@router.delete("/customers/{org_id}", status_code=204, dependencies=[Depends(require_permission("customers.delete"))])
async def delete_customer(org_id: str, session: AsyncSession = Depends(get_session)):
    org = await session.get(Organization, org_id)
    if org is not None:
        await session.delete(org)


# ── Users (cross-org) ─────────────────────────────────────────────────────────


@router.get("/users", dependencies=[Depends(require_permission("users.read"))])
async def list_users(organizationId: str | None = None, session: AsyncSession = Depends(get_session)):
    stmt = select(User).order_by(User.created_at.desc())
    if organizationId:
        stmt = stmt.where(User.organization_id == organizationId)
    rows = (await session.execute(stmt)).scalars().all()
    orgs = {o.id: o.name for o in (await session.execute(select(Organization))).scalars().all()}
    return {"users": [ser_user(u, org_name=orgs.get(u.organization_id)) for u in rows]}


@router.post("/users", status_code=201, dependencies=[Depends(require_permission("users.write"))])
async def create_user(body: PlatformUserBody, session: AsyncSession = Depends(get_session)):
    if await session.get(Organization, body.organizationId) is None:
        raise HTTPException(status_code=400, detail="unknown organization")
    dupe = (await session.execute(select(User).where(User.email == body.email))).scalars().first()
    if dupe is not None:
        raise HTTPException(status_code=409, detail="email already registered")
    role = await _role(session, body.roleSlug)
    u = User(
        organization_id=body.organizationId,
        email=body.email,
        password_hash=hash_password(body.password),
        role=Role.admin if role.slug != "customer-member" else Role.member,
        role_id=role.id,
        is_platform_staff=role.scope.value == "platform",
    )
    session.add(u)
    await session.flush()
    await session.refresh(u)
    return {"user": ser_user(u)}


@router.patch("/users/{user_id}", dependencies=[Depends(require_permission("users.write"))])
async def update_user(
    user_id: str,
    body: PlatformUserPatch,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(current_principal),
):
    u = await session.get(User, user_id)
    if u is None:
        raise HTTPException(status_code=404, detail="user not found")
    demotes = bool(body.roleSlug) and body.roleSlug != "integration-admin"
    disables = body.isActive is False
    if _is_active_platform_admin(u) and (demotes or disables):
        if u.id == principal.user_id:
            raise HTTPException(status_code=400, detail="you cannot remove your own admin access")
        await _assert_keeps_a_platform_admin(session, u)
    if body.roleSlug:
        role = await _role(session, body.roleSlug)
        u.role_id = role.id
        u.is_platform_staff = role.scope.value == "platform"
    if body.password:
        u.password_hash = hash_password(body.password)
    if body.isActive is not None:
        u.is_active = body.isActive
    await session.flush()
    await session.refresh(u)
    return {"user": ser_user(u)}


@router.delete("/users/{user_id}", status_code=204, dependencies=[Depends(require_permission("users.delete"))])
async def delete_user(
    user_id: str,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(current_principal),
):
    u = await session.get(User, user_id)
    if u is None:
        return
    if u.id == principal.user_id:
        raise HTTPException(status_code=400, detail="you cannot delete your own account")
    if _is_active_platform_admin(u):
        await _assert_keeps_a_platform_admin(session, u)
    await session.delete(u)


@router.get("/roles", dependencies=[Depends(require_permission("users.read"))])
async def list_roles(session: AsyncSession = Depends(get_session)):
    roles = (await session.execute(select(RbacRole).order_by(RbacRole.scope, RbacRole.name))).scalars().all()
    return {"roles": [ser_role(r) for r in roles]}
