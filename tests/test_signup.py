"""Self-serve signup: password register, the SIGNUP_ENABLED gate, and the Google
`mode=signup` path that provisions a whole new tenant."""

from __future__ import annotations

import uuid

import httpx
import pytest
from fastapi import HTTPException
from httpx import ASGITransport
from sqlalchemy import func, select, text

from dripstack.api.routes import sso
from dripstack.db import Organization, User
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


def _fresh_email() -> str:
    """Unique per run — User.email is globally unique, so a fixed address would
    pass once and 409 on every re-run."""
    return f"signup-{uuid.uuid4().hex[:10]}@example.com"


def _reset_settings():
    from dripstack.config import settings

    settings.cache_clear()


async def _org_count() -> int:
    async with session_scope() as s:
        return (await s.execute(select(func.count()).select_from(Organization))).scalar_one()


async def _cleanup(email: str):
    async with session_scope() as s:
        user = (await s.execute(select(User).where(User.email == email))).scalars().first()
        if user is not None:
            org = await s.get(Organization, user.organization_id)
            await s.delete(user)
            if org is not None:
                await s.delete(org)


# ── Password signup ───────────────────────────────────────────────────────────


async def test_register_creates_org_and_working_token():
    if not await _db_up():
        pytest.skip("DB not reachable")
    email = _fresh_email()
    try:
        async with httpx.AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
            r = await c.post(
                "/api/v1/auth/register",
                json={"orgName": "Acme Signup Test", "email": email, "password": "SuperSecret!23"},
            )
            assert r.status_code == 201, r.text
            body = r.json()
            assert body["organization"]["name"] == "Acme Signup Test"

            # The returned token must actually authenticate, and land in the new org.
            me = await c.get("/api/v1/auth/me", headers={"authorization": f"Bearer {body['accessToken']}"})
            assert me.status_code == 200
            assert me.json()["organizationId"] == body["organization"]["id"]

            # Same email twice → 409, not a second org.
            dupe = await c.post(
                "/api/v1/auth/register",
                json={"orgName": "Acme Again", "email": email, "password": "SuperSecret!23"},
            )
            assert dupe.status_code == 409
    finally:
        await _cleanup(email)


async def test_register_404s_when_signup_disabled(monkeypatch):
    if not await _db_up():
        pytest.skip("DB not reachable")
    monkeypatch.setenv("SIGNUP_ENABLED", "false")
    _reset_settings()
    try:
        async with httpx.AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
            r = await c.post(
                "/api/v1/auth/register",
                json={"orgName": "Nope", "email": _fresh_email(), "password": "SuperSecret!23"},
            )
            # 404 rather than 403 — a disabled signup should look absent.
            assert r.status_code == 404
            assert (await c.get("/api/v1/auth/providers")).json()["signup"] is False
    finally:
        monkeypatch.delenv("SIGNUP_ENABLED", raising=False)
        _reset_settings()


# ── Google signup ─────────────────────────────────────────────────────────────


def test_signup_state_carries_mode_and_org_name():
    assert sso._verify_google_state(sso._sign_google_state()) == ("signin", "")
    assert sso._verify_google_state(sso._sign_google_state("signup", "Acme")) == ("signup", "Acme")
    # Cross-flow replay is still refused now that the payload has grown.
    with pytest.raises(HTTPException):
        sso._verify_google_state(sso._sign_state("org-123"))


def _stub_google(monkeypatch, email: str, verified: bool = True):
    async def fake_discover(issuer):
        return {
            "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_endpoint": "https://oauth2.googleapis.com/token",
            "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
        }

    async def fake_exchange(token_endpoint, **kw):
        return {"access_token": "at-google"}

    async def fake_userinfo(endpoint, token):
        return {"email": email, "email_verified": verified}

    monkeypatch.setattr(sso, "discover", fake_discover)
    monkeypatch.setattr(sso, "exchange_code", fake_exchange)
    monkeypatch.setattr(sso, "fetch_userinfo", fake_userinfo)


async def test_google_signup_provisions_a_new_tenant(monkeypatch):
    if not await _db_up():
        pytest.skip("DB not reachable")
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "cid")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "sec")
    _reset_settings()
    email = _fresh_email()
    try:
        _stub_google(monkeypatch, email)
        before = await _org_count()
        async with httpx.AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
            state = sso._sign_google_state("signup", "Google Signup Co")
            r = await c.get(f"/api/v1/auth/google/callback?code=abc&state={state}")
            assert r.status_code == 302
            assert "/sso/callback#" in r.headers["location"] and "accessToken=" in r.headers["location"]

        assert await _org_count() == before + 1
        async with session_scope() as s:
            user = (await s.execute(select(User).where(User.email == email))).scalars().first()
            assert user is not None
            org = await s.get(Organization, user.organization_id)
            assert org.name == "Google Signup Co"
            # settings={} so the org honours the env EMAIL_PROVIDER rather than
            # pinning itself to "log" the way platform.create_customer does.
            assert org.settings == {}
            # Unusable hash — a Google-provisioned account must never be able to
            # authenticate with a password.
            assert user.password_hash == "!sso-no-password"
    finally:
        await _cleanup(email)
        for k in ("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"):
            monkeypatch.delenv(k, raising=False)
        _reset_settings()


async def test_google_signup_with_existing_email_just_signs_in(monkeypatch):
    if not await _db_up():
        pytest.skip("DB not reachable")
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "cid")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "sec")
    _reset_settings()
    try:
        _stub_google(monkeypatch, "demo@dripstack.dev")
        before = await _org_count()
        async with httpx.AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
            state = sso._sign_google_state("signup", "Should Not Be Created")
            r = await c.get(f"/api/v1/auth/google/callback?code=abc&state={state}")
            assert r.status_code == 302
            assert "accessToken=" in r.headers["location"]
        # The whole point: a signup click from an existing account is a login.
        assert await _org_count() == before
    finally:
        for k in ("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"):
            monkeypatch.delenv(k, raising=False)
        _reset_settings()


async def test_google_signup_start_refuses_blank_org_and_disabled_signup(monkeypatch):
    if not await _db_up():
        pytest.skip("DB not reachable")
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "cid")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "sec")
    _reset_settings()
    try:
        _stub_google(monkeypatch, "x@example.com")
        async with httpx.AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
            # Blank orgName is rejected BEFORE redirecting to Google — bouncing
            # the user back after they authenticate is a wasted round trip.
            blank = await c.get("/api/v1/auth/google/start?mode=signup&orgName=%20")
            assert blank.status_code == 400

            ok = await c.get("/api/v1/auth/google/start?mode=signup&orgName=Acme")
            assert ok.status_code in (302, 307)

            monkeypatch.setenv("SIGNUP_ENABLED", "false")
            _reset_settings()
            off = await c.get("/api/v1/auth/google/start?mode=signup&orgName=Acme")
            assert off.status_code == 404
            # Plain sign-in is unaffected by the signup switch.
            assert (await c.get("/api/v1/auth/google/start")).status_code in (302, 307)
    finally:
        for k in ("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "SIGNUP_ENABLED"):
            monkeypatch.delenv(k, raising=False)
        _reset_settings()
