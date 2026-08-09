"""Auth routes (register / login / refresh / me) with RBAC awareness."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...config import settings
from ...db import Organization, RbacRole, Role, User
from ..audit import record_audit
from ..auth import (
    Principal,
    auth_context_for,
    current_principal,
    get_session,
    hash_password,
    sign_tokens,
    tenant_db,
    verify_password,
    verify_refresh,
)
from ..ratelimit import limiter
from ..serialize import organization as ser_org

router = APIRouter(prefix="/api/v1/auth")


class RegisterBody(BaseModel):
    orgName: str = Field(min_length=1)
    email: str = Field(min_length=3)
    password: str = Field(min_length=8)


class LoginBody(BaseModel):
    email: str
    password: str


class RefreshBody(BaseModel):
    refreshToken: str


async def _role_id(session: AsyncSession, slug: str) -> str | None:
    role = (await session.execute(select(RbacRole).where(RbacRole.slug == slug))).scalars().first()
    return role.id if role else None


@router.post("/register", status_code=201)
# Self-serve tenant creation is the most abusable route in the app: unauthenticated,
# and every call writes an Organization. The `request` parameter is not unused —
# slowapi resolves the client IP from it, and the decorator raises at import time
# without it.
@limiter.limit("5/hour")
async def register(body: RegisterBody, request: Request, session: AsyncSession = Depends(get_session)):
    # 404 rather than 403: a disabled signup should look like a route that was
    # never deployed, not like one worth probing.
    if not settings().SIGNUP_ENABLED:
        raise HTTPException(status_code=404, detail="Not Found")

    existing = (await session.execute(select(User).where(User.email == body.email))).scalars().first()
    if existing is not None:
        raise HTTPException(status_code=409, detail="email already registered")

    org = Organization(name=body.orgName, settings={})
    session.add(org)
    await session.flush()
    user = User(
        organization_id=org.id,
        email=body.email,
        password_hash=hash_password(body.password),
        role=Role.admin,
        role_id=await _role_id(session, "customer-admin"),
    )
    session.add(user)
    await session.flush()
    await session.refresh(user)

    # Signup is the one event that brings a tenant into existence; without this
    # it would be the only auth action with no trail.
    await record_audit(
        organization_id=org.id,
        action="auth.register",
        actor_id=user.id,
        actor_label=user.email,
        meta={"orgName": org.name},
        request=request,
    )

    tokens = sign_tokens(auth_context_for(user))
    return {**tokens, "organization": {"id": org.id, "name": org.name}}


@router.post("/login")
async def login(body: LoginBody, request: Request, session: AsyncSession = Depends(get_session)):
    user = (await session.execute(select(User).where(User.email == body.email))).scalars().first()
    if user is None or not verify_password(body.password, user.password_hash):
        if user is not None:
            await record_audit(
                organization_id=user.organization_id,
                action="auth.login_failed",
                actor_label=body.email,
                request=request,
            )
        raise HTTPException(status_code=401, detail="invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=401, detail="account disabled")
    tokens = sign_tokens(auth_context_for(user))
    await record_audit(
        organization_id=user.organization_id,
        action="auth.login",
        actor_id=user.id,
        actor_label=user.email,
        request=request,
    )
    return tokens


@router.post("/refresh")
async def refresh(body: RefreshBody):
    try:
        ctx = verify_refresh(body.refreshToken)
    except Exception as err:  # noqa: BLE001
        raise HTTPException(status_code=401, detail="invalid refresh token") from err
    return sign_tokens(ctx)


@router.get("/me")
async def me(principal: Principal = Depends(current_principal), db=Depends(tenant_db)):
    org = await db.first(Organization)
    return {
        "userId": principal.user_id,
        "organizationId": principal.organization_id,
        "role": {"slug": principal.role_slug, "scope": principal.scope},
        "isPlatform": principal.is_platform,
        "permissions": sorted(principal.permissions),
        "organization": ser_org(org),
    }
