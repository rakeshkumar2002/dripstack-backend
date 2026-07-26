"""Auth: passwords, JWT, RBAC principals, and FastAPI dependencies.

`require_user` validates the access token. `current_principal` additionally
loads the user's role + permissions. `require_permission(key)` / `require_platform`
gate routes. `tenant_db` yields a tenant-scoped session for org-scoped routes;
platform routes use the raw session (cross-org) behind `require_platform`.
"""

from __future__ import annotations

import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime

import jwt
from fastapi import Depends, Header, HTTPException, Request
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..db import ApiKey, User
from ..db.session import session_scope
from ..db.tenant import TenantSession, for_org
from ..logging import logger
from ..shared import sha256_hex

_pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")


@dataclass
class AuthContext:
    user_id: str
    organization_id: str
    role: str  # rbac role slug (or legacy enum value)
    scope: str = "organization"
    is_platform: bool = False


@dataclass
class Principal:
    user_id: str
    organization_id: str
    role_slug: str | None
    scope: str
    is_platform: bool
    permissions: set[str] = field(default_factory=set)

    def has(self, key: str) -> bool:
        return key in self.permissions


def hash_password(pw: str) -> str:
    return _pwd.hash(pw)


def verify_password(pw: str, hashed: str) -> bool:
    return _pwd.verify(pw, hashed)


def _ttl_seconds(ttl: str) -> int:
    unit = ttl[-1]
    mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}.get(unit)
    if mult is None:
        return int(ttl)
    return int(ttl[:-1]) * mult


def _sign(ctx: AuthContext, secret: str, ttl: str) -> str:
    payload = {
        "sub": ctx.user_id,
        "org": ctx.organization_id,
        "role": ctx.role,
        "scope": ctx.scope,
        "plt": ctx.is_platform,
        "exp": int(time.time()) + _ttl_seconds(ttl),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def sign_tokens(ctx: AuthContext) -> dict[str, str]:
    s = settings()
    return {
        "accessToken": _sign(ctx, s.JWT_ACCESS_SECRET, s.JWT_ACCESS_TTL),
        "refreshToken": _sign(ctx, s.JWT_REFRESH_SECRET, s.JWT_REFRESH_TTL),
    }


def auth_context_for(user: User) -> AuthContext:
    """Build the token context from a user's RBAC role (falls back to legacy enum)."""
    role = user.rbac_role
    return AuthContext(
        user_id=user.id,
        organization_id=user.organization_id,
        role=role.slug if role else user.role.value,
        scope=(role.scope.value if role else "organization"),
        is_platform=bool(user.is_platform_staff),
    )


def verify_refresh(token: str) -> AuthContext:
    d = jwt.decode(token, settings().JWT_REFRESH_SECRET, algorithms=["HS256"])
    return AuthContext(
        user_id=str(d["sub"]),
        organization_id=str(d["org"]),
        role=str(d["role"]),
        scope=str(d.get("scope", "organization")),
        is_platform=bool(d.get("plt", False)),
    )


# ── Request dependencies ──────────────────────────────────────────────────────


async def get_session() -> AsyncIterator[AsyncSession]:
    async with session_scope() as session:
        yield session


def require_user(authorization: str | None = Header(default=None)) -> AuthContext:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    try:
        d = jwt.decode(authorization[7:], settings().JWT_ACCESS_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError as err:
        raise HTTPException(status_code=401, detail="invalid or expired token") from err
    return AuthContext(
        user_id=str(d["sub"]),
        organization_id=str(d["org"]),
        role=str(d["role"]),
        scope=str(d.get("scope", "organization")),
        is_platform=bool(d.get("plt", False)),
    )


async def tenant_db(
    auth: AuthContext = Depends(require_user),
    session: AsyncSession = Depends(get_session),
) -> TenantSession:
    return for_org(session, auth.organization_id)


async def current_principal(
    auth: AuthContext = Depends(require_user),
    session: AsyncSession = Depends(get_session),
) -> Principal:
    """Load the user's role + permission set (one selectin query via rbac_role)."""
    user = await session.get(User, auth.user_id)
    permissions: set[str] = set()
    role_slug: str | None = None
    scope = auth.scope
    is_platform = auth.is_platform
    if user is not None:
        if not user.is_active:
            raise HTTPException(status_code=403, detail="account disabled")
        is_platform = bool(user.is_platform_staff)
        if user.rbac_role is not None:
            role_slug = user.rbac_role.slug
            scope = user.rbac_role.scope.value
            permissions = {p.key for p in user.rbac_role.permissions}
    return Principal(
        user_id=auth.user_id,
        organization_id=auth.organization_id,
        role_slug=role_slug,
        scope=scope,
        is_platform=is_platform,
        permissions=permissions,
    )


def require_permission(key: str):
    async def dep(principal: Principal = Depends(current_principal)) -> Principal:
        if not principal.has(key):
            raise HTTPException(status_code=403, detail=f"missing permission: {key}")
        return principal

    return dep


async def require_platform(principal: Principal = Depends(current_principal)) -> Principal:
    if principal.scope != "platform" and not principal.is_platform:
        raise HTTPException(status_code=403, detail="platform access required")
    return principal


async def require_api_key(
    request: Request,
    x_api_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> AuthContext:
    raw = x_api_key
    if not raw and authorization and authorization.startswith("Bearer "):
        raw = authorization[7:]
    if not raw:
        raise HTTPException(status_code=401, detail="missing api key")

    async with session_scope() as session:
        key = (await session.execute(select(ApiKey).where(ApiKey.hashed_key == sha256_hex(raw)))).scalars().first()
        if key is None:
            raise HTTPException(status_code=401, detail="invalid api key")
        try:
            key.last_used_at = datetime.now(UTC)
        except Exception as err:  # noqa: BLE001
            logger.warning("failed to update apiKey.lastUsedAt", err=str(err))
        return AuthContext(user_id="apikey", organization_id=key.organization_id, role="member")
