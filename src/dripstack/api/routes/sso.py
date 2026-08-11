"""SSO via OpenID Connect (OIDC).

Two surfaces:

1. **Config** (`/api/v1/sso`) — tenant-scoped admin CRUD for the per-org OIDC
   connection (issuer, client id/secret, provisioning policy). Secrets are write
   only; reads return a masked view.

2. **Login flow** (`/api/v1/auth/sso/...`) — the standard OIDC authorization-code
   flow:
       start → provider login → callback → token exchange → userinfo
             → match/provision user → issue DripStack JWTs → dashboard.

   `state` is a short-lived signed JWT binding the org + a nonce, so the callback
   can't be replayed across orgs or forged. The three network calls (discovery,
   token exchange, userinfo) are thin module functions so tests can stub them.
"""

from __future__ import annotations

import secrets
import time
from urllib.parse import urlencode

import httpx
import jwt
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy import select

from ...config import settings
from ...db import Organization, RbacRole, Role, SsoConnection, User
from ...db.session import session_scope
from ...db.tenant import TenantSession
from ...logging import logger
from ...shared import UnsafeUrlError, assert_safe_outbound_url
from ..audit import record_audit
from ..auth import Principal, auth_context_for, require_permission, sign_tokens, tenant_db
from ..serialize import sso_connection as ser_sso

router = APIRouter(prefix="/api/v1")

_STATE_TTL_SECONDS = 600
_DISCOVERY_CACHE: dict[str, tuple[float, dict]] = {}
_DISCOVERY_TTL = 3600


# ── OIDC network calls (stubbed in tests) ─────────────────────────────────────


async def discover(issuer: str) -> dict:
    """Fetch (and briefly cache) the OIDC discovery document."""
    cached = _DISCOVERY_CACHE.get(issuer)
    if cached and cached[0] > time.time():
        return cached[1]
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    # Re-checked at fetch time, not only when the connection was saved: DNS can
    # change under a stored issuer.
    assert_safe_outbound_url(url)
    async with httpx.AsyncClient(timeout=10) as client:
        res = await client.get(url)
    if res.status_code >= 300:
        raise RuntimeError(f"oidc discovery failed: {res.status_code}")
    doc = res.json()
    _DISCOVERY_CACHE[issuer] = (time.time() + _DISCOVERY_TTL, doc)
    return doc


async def exchange_code(token_endpoint: str, *, code: str, redirect_uri: str, client_id: str, client_secret: str) -> dict:
    # The endpoint comes from the provider's discovery document — untrusted input.
    assert_safe_outbound_url(token_endpoint)
    async with httpx.AsyncClient(timeout=10) as client:
        res = await client.post(
            token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "client_secret": client_secret,
            },
            headers={"Accept": "application/json"},
        )
    if res.status_code >= 300:
        raise RuntimeError(f"oidc token exchange failed: {res.status_code}")
    return res.json()


async def fetch_userinfo(userinfo_endpoint: str, access_token: str) -> dict:
    assert_safe_outbound_url(userinfo_endpoint)
    async with httpx.AsyncClient(timeout=10) as client:
        res = await client.get(userinfo_endpoint, headers={"Authorization": f"Bearer {access_token}"})
    if res.status_code >= 300:
        raise RuntimeError(f"oidc userinfo failed: {res.status_code}")
    return res.json()


# ── State token (signed, short-lived) ─────────────────────────────────────────


def _sign_state(org_id: str) -> str:
    payload = {"org": org_id, "typ": "sso_state", "exp": int(time.time()) + _STATE_TTL_SECONDS}
    return jwt.encode(payload, settings().JWT_ACCESS_SECRET, algorithm="HS256")


def _verify_state(state: str) -> str:
    try:
        d = jwt.decode(state, settings().JWT_ACCESS_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError as err:
        raise HTTPException(status_code=400, detail="invalid or expired SSO state") from err
    if d.get("typ") != "sso_state" or "org" not in d:
        raise HTTPException(status_code=400, detail="invalid SSO state")
    return str(d["org"])


def _redirect_uri() -> str:
    return settings().APP_BASE_URL.rstrip("/") + "/api/v1/auth/sso/callback"


# ── Core: resolve a verified SSO email to DripStack tokens ─────────────────────


def _email_allowed(conn: SsoConnection, email: str) -> bool:
    if not conn.allowed_domain:
        return True
    return email.lower().endswith("@" + conn.allowed_domain.lower().lstrip("@"))


async def resolve_sso_user(session, conn: SsoConnection, email: str) -> User:
    """Find the org user for a verified SSO email, provisioning if configured.

    Raises HTTPException(403) when the user doesn't exist and auto-provision is
    off, or the user is disabled, or the email domain isn't allowed.
    """
    email = email.strip().lower()
    if not _email_allowed(conn, email):
        raise HTTPException(status_code=403, detail="email domain not permitted for SSO")

    user = (
        await session.execute(
            select(User).where(User.organization_id == conn.organization_id, User.email == email)
        )
    ).scalars().first()

    if user is not None:
        if not user.is_active:
            raise HTTPException(status_code=403, detail="account disabled")
        return user

    if not conn.auto_provision:
        raise HTTPException(status_code=403, detail="no account for this email; ask an admin to invite you")

    role = (
        await session.execute(select(RbacRole).where(RbacRole.slug == conn.default_role_slug))
    ).scalars().first()
    if role is None:
        raise HTTPException(status_code=500, detail="default SSO role not found")

    # Provisioned users have no password; an unusable hash blocks password login.
    user = User(
        organization_id=conn.organization_id,
        email=email,
        password_hash="!sso-no-password",
        role=Role.admin if role.slug == "customer-admin" else Role.member,
        role_id=role.id,
    )
    session.add(user)
    await session.flush()
    await session.refresh(user)
    return user


# ── Login flow endpoints (public) ─────────────────────────────────────────────


@router.get("/auth/sso/{org_id}/start")
async def sso_start(org_id: str):
    async with session_scope() as session:
        conn = (
            await session.execute(select(SsoConnection).where(SsoConnection.organization_id == org_id))
        ).scalars().first()
        if conn is None or not conn.enabled:
            raise HTTPException(status_code=404, detail="SSO not enabled for this organization")
        issuer, client_id = conn.issuer, conn.client_id

    doc = await discover(issuer)
    authorize_endpoint = doc.get("authorization_endpoint")
    if not authorize_endpoint:
        raise HTTPException(status_code=502, detail="OIDC provider missing authorization_endpoint")

    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": _redirect_uri(),
        "scope": "openid email profile",
        "state": _sign_state(org_id),
    }
    return RedirectResponse(url=f"{authorize_endpoint}?{urlencode(params)}", status_code=302)


@router.get("/auth/sso/callback")
async def sso_callback(request: Request, code: str | None = None, state: str | None = None, error: str | None = None):
    dashboard = settings().DASHBOARD_URL.rstrip("/")
    if error:
        return RedirectResponse(url=f"{dashboard}/login?sso_error={error}", status_code=302)
    if not code or not state:
        raise HTTPException(status_code=400, detail="missing code or state")

    org_id = _verify_state(state)

    async with session_scope() as session:
        conn = (
            await session.execute(select(SsoConnection).where(SsoConnection.organization_id == org_id))
        ).scalars().first()
        if conn is None or not conn.enabled:
            raise HTTPException(status_code=404, detail="SSO not enabled for this organization")

        doc = await discover(conn.issuer)
        token_endpoint = doc.get("token_endpoint")
        userinfo_endpoint = doc.get("userinfo_endpoint")
        if not token_endpoint or not userinfo_endpoint:
            raise HTTPException(status_code=502, detail="OIDC provider missing token/userinfo endpoint")

        tokens = await exchange_code(
            token_endpoint,
            code=code,
            redirect_uri=_redirect_uri(),
            client_id=conn.client_id,
            client_secret=conn.client_secret,
        )
        access_token = tokens.get("access_token")
        if not access_token:
            raise HTTPException(status_code=502, detail="OIDC token response missing access_token")

        info = await fetch_userinfo(userinfo_endpoint, access_token)
        email = info.get("email")
        if not email:
            raise HTTPException(status_code=502, detail="OIDC userinfo missing email")
        if info.get("email_verified") is False:
            raise HTTPException(status_code=403, detail="email not verified by SSO provider")

        user = await resolve_sso_user(session, conn, email)
        ctx = auth_context_for(user)
        user_id, org = user.id, user.organization_id

    issued = sign_tokens(ctx)
    await record_audit(
        organization_id=org,
        action="auth.sso_login",
        actor_id=user_id,
        actor_label=email,
        meta={"issuer": conn.issuer},
        request=request,
    )
    frag = urlencode({"accessToken": issued["accessToken"], "refreshToken": issued["refreshToken"]})
    return RedirectResponse(url=f"{dashboard}/sso/callback#{frag}", status_code=302)


# ── SSO discovery (public) ────────────────────────────────────────────────────


class SsoDiscoverBody(BaseModel):
    email: str = Field(min_length=3)


@router.post("/auth/sso/discover")
async def sso_discover(body: SsoDiscoverBody):
    """Map a work email to the org whose SSO connection claims its domain.

    Lets the login page ask for an email instead of an organization id, which no
    user knows. Only ever reveals whether a domain has SSO configured — never
    whether a given account exists.
    """
    email = body.email.strip().lower()
    if "@" not in email:
        raise HTTPException(status_code=400, detail="enter a full email address")

    async with session_scope() as session:
        conns = (
            await session.execute(
                select(SsoConnection).where(SsoConnection.enabled.is_(True), SsoConnection.allowed_domain.isnot(None))
            )
        ).scalars().all()
        # Reuses the same matcher the callback enforces, so discovery and the
        # actual policy can never drift apart.
        match = next((c for c in conns if _email_allowed(c, email)), None)

    if match is None:
        raise HTTPException(status_code=404, detail="no SSO configured for this email domain")
    return {"orgId": match.organization_id}


# ── Google sign-in (platform-level) ───────────────────────────────────────────
#
# Distinct from the per-org OIDC connection above: one Google OAuth app for the
# whole deployment, so there is no org to choose before signing in. That works
# because User.email is globally unique by design (models.py:128) — a verified
# Google address resolves to exactly one account, or to none.
#
# Unknown emails are rejected rather than provisioned. A platform-wide Google
# button that creates accounts would let anyone with a Gmail address in.


def _google_configured() -> bool:
    s = settings()
    return bool(s.GOOGLE_CLIENT_ID and s.GOOGLE_CLIENT_SECRET)


def _google_redirect_uri() -> str:
    return settings().APP_BASE_URL.rstrip("/") + "/api/v1/auth/google/callback"


def _sign_google_state(mode: str = "signin", org_name: str = "") -> str:
    """Carry the caller's intent to the callback.

    The org name for a signup goes in here rather than in a query parameter on
    the callback URL precisely because this is signed — otherwise anyone could
    rewrite which organization gets created mid-flow.
    """
    payload = {
        "typ": "google_state",
        "mode": mode,
        "org": org_name,
        "nonce": secrets.token_urlsafe(16),
        "exp": int(time.time()) + _STATE_TTL_SECONDS,
    }
    return jwt.encode(payload, settings().JWT_ACCESS_SECRET, algorithm="HS256")


def _verify_google_state(state: str) -> tuple[str, str]:
    """Returns (mode, org_name)."""
    try:
        d = jwt.decode(state, settings().JWT_ACCESS_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError as err:
        raise HTTPException(status_code=400, detail="invalid or expired sign-in state") from err
    # Without this the org-scoped SSO state above would be accepted here, and a
    # state minted for one flow could be replayed into the other.
    if d.get("typ") != "google_state":
        raise HTTPException(status_code=400, detail="invalid sign-in state")
    mode = d.get("mode") or "signin"
    return ("signup" if mode == "signup" else "signin"), str(d.get("org") or "")


async def _provision_signup_org(session, *, org_name: str, email: str) -> User:
    """Create a brand-new tenant and its first customer-admin from a Google signup.

    settings={} rather than platform.create_customer's {"emailProvider": "log"} —
    a self-serve org should honour whatever EMAIL_PROVIDER the deployment is
    configured with, since a per-org setting silently wins over the env
    (providers/email.py:126).
    """
    org = Organization(name=org_name.strip(), settings={})
    session.add(org)
    await session.flush()

    role = (await session.execute(select(RbacRole).where(RbacRole.slug == "customer-admin"))).scalars().first()
    if role is None:
        raise HTTPException(status_code=500, detail="customer-admin role not found; run the seed")

    user = User(
        organization_id=org.id,
        email=email,
        # Same unusable hash resolve_sso_user() uses — a bcrypt check can never
        # succeed, so this account cannot also become a password account.
        password_hash="!sso-no-password",
        role=Role.admin,
        role_id=role.id,
    )
    session.add(user)
    await session.flush()
    await session.refresh(user)
    logger.info("google signup provisioned org", org_id=org.id, email=email)
    return user


@router.get("/auth/providers")
async def auth_providers():
    """Public: which buttons the login and signup pages should render."""
    return {"google": _google_configured(), "signup": settings().SIGNUP_ENABLED}


@router.get("/auth/google/start")
async def google_start(mode: str = "signin", orgName: str = ""):
    if not _google_configured():
        raise HTTPException(status_code=404, detail="Google sign-in is not configured")

    signup = mode == "signup"
    # Refuse before redirecting to Google. Discovering the problem after the user
    # has authenticated means bouncing them back with nothing to show for it.
    if signup:
        if not settings().SIGNUP_ENABLED:
            raise HTTPException(status_code=404, detail="Not Found")
        if not orgName.strip():
            raise HTTPException(status_code=400, detail="orgName is required to sign up")

    doc = await discover(settings().GOOGLE_ISSUER)
    authorize_endpoint = doc.get("authorization_endpoint")
    if not authorize_endpoint:
        raise HTTPException(status_code=502, detail="Google discovery missing authorization_endpoint")

    params = {
        "response_type": "code",
        "client_id": settings().GOOGLE_CLIENT_ID,
        "redirect_uri": _google_redirect_uri(),
        "scope": "openid email profile",
        "state": _sign_google_state("signup" if signup else "signin", orgName.strip()),
    }
    return RedirectResponse(url=f"{authorize_endpoint}?{urlencode(params)}", status_code=302)


@router.get("/auth/google/callback")
async def google_callback(request: Request, code: str | None = None, state: str | None = None, error: str | None = None):
    dashboard = settings().DASHBOARD_URL.rstrip("/")
    # Failures redirect to the login page rather than rendering a raw API error:
    # the browser is mid-navigation here, not making an XHR.
    if error:
        return RedirectResponse(url=f"{dashboard}/login?sso_error={error}", status_code=302)
    if not _google_configured():
        raise HTTPException(status_code=404, detail="Google sign-in is not configured")
    if not code or not state:
        raise HTTPException(status_code=400, detail="missing code or state")

    mode, org_name = _verify_google_state(state)

    doc = await discover(settings().GOOGLE_ISSUER)
    token_endpoint = doc.get("token_endpoint")
    userinfo_endpoint = doc.get("userinfo_endpoint")
    if not token_endpoint or not userinfo_endpoint:
        raise HTTPException(status_code=502, detail="Google discovery missing token/userinfo endpoint")

    tokens = await exchange_code(
        token_endpoint,
        code=code,
        redirect_uri=_google_redirect_uri(),
        client_id=settings().GOOGLE_CLIENT_ID or "",
        client_secret=settings().GOOGLE_CLIENT_SECRET or "",
    )
    access_token = tokens.get("access_token")
    if not access_token:
        raise HTTPException(status_code=502, detail="Google token response missing access_token")

    info = await fetch_userinfo(userinfo_endpoint, access_token)
    email = (info.get("email") or "").strip().lower()
    if not email:
        raise HTTPException(status_code=502, detail="Google userinfo missing email")
    # Google always sets this; require it truthy rather than merely "not False",
    # so a provider that omits the claim cannot slip an unverified address past.
    if not info.get("email_verified"):
        return RedirectResponse(url=f"{dashboard}/login?sso_error=email_not_verified", status_code=302)

    created = False
    async with session_scope() as session:
        user = (await session.execute(select(User).where(User.email == email))).scalars().first()

        if user is None and mode == "signup":
            # Re-check the flag at callback time, not just at start: the state is
            # valid for 10 minutes, which is long enough for signup to be turned
            # off in between.
            if not settings().SIGNUP_ENABLED:
                return RedirectResponse(url=f"{dashboard}/login?sso_error=signup_disabled", status_code=302)
            if not org_name:
                return RedirectResponse(url=f"{dashboard}/signup?sso_error=org_name_required", status_code=302)
            user = await _provision_signup_org(session, org_name=org_name, email=email)
            created = True
        elif user is None:
            logger.info("google sign-in rejected: no account", email=email)
            return RedirectResponse(url=f"{dashboard}/login?sso_error=no_account", status_code=302)

        # An existing account signing up is just a login — people do not remember
        # which button they used last time, and a second org would be wrong.
        if not user.is_active:
            return RedirectResponse(url=f"{dashboard}/login?sso_error=account_disabled", status_code=302)
        ctx = auth_context_for(user)
        user_id, org = user.id, user.organization_id

    issued = sign_tokens(ctx)
    await record_audit(
        organization_id=org,
        action="auth.google_signup" if created else "auth.google_login",
        actor_id=user_id,
        actor_label=email,
        meta={"issuer": settings().GOOGLE_ISSUER},
        request=request,
    )
    frag = urlencode({"accessToken": issued["accessToken"], "refreshToken": issued["refreshToken"]})
    return RedirectResponse(url=f"{dashboard}/sso/callback#{frag}", status_code=302)


# ── Config endpoints (tenant-scoped admin) ────────────────────────────────────


class SsoConfigBody(BaseModel):
    issuer: str = Field(min_length=1)
    clientId: str = Field(min_length=1)
    clientSecret: str | None = None  # omit on update to keep the stored secret
    enabled: bool = True
    autoProvision: bool = False
    allowedDomain: str | None = None
    defaultRoleSlug: str = "customer-member"


@router.get("/sso", dependencies=[Depends(require_permission("integrations.read"))])
async def get_sso(db: TenantSession = Depends(tenant_db)):
    conn = await db.first(SsoConnection)
    if conn is None:
        return {"configured": False}
    return ser_sso(conn)


@router.put("/sso")
async def upsert_sso(
    body: SsoConfigBody,
    request: Request,
    db: TenantSession = Depends(tenant_db),
    principal: Principal = Depends(require_permission("integrations.write")),
):
    if not body.issuer.lower().startswith("https://"):
        raise HTTPException(status_code=400, detail="issuer must be an https:// URL")
    # SSRF guard: discovery/token/userinfo are all fetched server-side from
    # this host, so it must not point at the compose network or metadata.
    try:
        assert_safe_outbound_url(body.issuer)
    except UnsafeUrlError as err:
        raise HTTPException(status_code=400, detail=str(err)) from err
    if body.defaultRoleSlug not in ("customer-admin", "customer-member"):
        raise HTTPException(status_code=400, detail="defaultRoleSlug must be a customer role")

    conn = await db.first(SsoConnection)
    if conn is None:
        if not body.clientSecret:
            raise HTTPException(status_code=400, detail="clientSecret is required to create an SSO connection")
        conn = await db.add(
            SsoConnection(
                provider="oidc",
                issuer=body.issuer,
                client_id=body.clientId,
                client_secret=body.clientSecret,
                enabled=body.enabled,
                auto_provision=body.autoProvision,
                allowed_domain=body.allowedDomain,
                default_role_slug=body.defaultRoleSlug,
            )
        )
    else:
        conn.issuer = body.issuer
        conn.client_id = body.clientId
        if body.clientSecret:
            conn.client_secret = body.clientSecret
        conn.enabled = body.enabled
        conn.auto_provision = body.autoProvision
        conn.allowed_domain = body.allowedDomain
        conn.default_role_slug = body.defaultRoleSlug
        await db.session.flush()

    await record_audit(
        organization_id=db.org_id,
        action="sso.configure",
        actor_id=principal.user_id,
        target=conn.id,
        meta={"issuer": conn.issuer, "enabled": conn.enabled},
        request=request,
    )
    logger.info("sso connection upserted", org_id=db.org_id, issuer=conn.issuer)
    return ser_sso(conn)


@router.delete("/sso", status_code=204, dependencies=[Depends(require_permission("integrations.write"))])
async def delete_sso(db: TenantSession = Depends(tenant_db)):
    conn = await db.first(SsoConnection)
    if conn is not None:
        await db.session.delete(conn)
