"""OIDC SSO: state signing, domain policy, user resolution/provisioning, and a
stubbed end-to-end authorization-code callback."""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest
from fastapi import HTTPException
from httpx import ASGITransport
from sqlalchemy import text

from dripstack.api.routes import sso
from dripstack.db.session import session_scope

# ── Unit: state token ─────────────────────────────────────────────────────────


def test_state_roundtrip():
    state = sso._sign_state("org-123")
    assert sso._verify_state(state) == "org-123"


def test_state_forged_rejected():
    with pytest.raises(HTTPException):
        sso._verify_state("not-a-jwt")


def test_state_wrong_type_rejected():
    import jwt

    from dripstack.config import settings

    bad = jwt.encode({"org": "x", "typ": "other"}, settings().JWT_ACCESS_SECRET, algorithm="HS256")
    with pytest.raises(HTTPException):
        sso._verify_state(bad)


# ── Unit: domain policy ───────────────────────────────────────────────────────


def test_email_allowed():
    conn = SimpleNamespace(allowed_domain=None)
    assert sso._email_allowed(conn, "anyone@whatever.com")

    conn = SimpleNamespace(allowed_domain="acme.com")
    assert sso._email_allowed(conn, "jo@acme.com")
    assert sso._email_allowed(conn, "jo@ACME.com")
    assert not sso._email_allowed(conn, "jo@evil.com")

    conn = SimpleNamespace(allowed_domain="@acme.com")  # leading @ tolerated
    assert sso._email_allowed(conn, "jo@acme.com")


# ── App / DB tests (skippable) ────────────────────────────────────────────────


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


async def _admin_ctx(c):
    tok = (
        await c.post("/api/v1/auth/login", json={"email": "demo@dripstack.dev", "password": "DripStackDemo!23"})
    ).json()["accessToken"]
    headers = {"authorization": f"Bearer {tok}"}
    org_id = (await c.get("/api/v1/auth/me", headers=headers)).json()["organizationId"]
    return headers, org_id


async def test_sso_config_masks_secret_and_gates_writes():
    if not await _db_up():
        pytest.skip("DB not reachable")
    async with httpx.AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
        admin, _ = await _admin_ctx(c)

        # Non-https issuer rejected.
        bad = await c.put(
            "/api/v1/sso", headers=admin,
            json={"issuer": "http://insecure", "clientId": "cid", "clientSecret": "sec"},
        )
        assert bad.status_code == 400

        up = await c.put(
            "/api/v1/sso", headers=admin,
            json={"issuer": "https://idp.example.com", "clientId": "cid", "clientSecret": "supersecret",
                  "autoProvision": False, "allowedDomain": "dripstack.dev"},
        )
        assert up.status_code == 200
        body = up.json()
        # Secret must never be returned.
        assert "supersecret" not in str(body)
        assert body["clientSecretSet"] is True and body["issuer"] == "https://idp.example.com"

        got = (await c.get("/api/v1/sso", headers=admin)).json()
        assert got["configured"] is True and "supersecret" not in str(got)

        # Updating without clientSecret keeps the stored one.
        up2 = await c.put(
            "/api/v1/sso", headers=admin,
            json={"issuer": "https://idp.example.com", "clientId": "cid2", "enabled": True},
        )
        assert up2.json()["clientId"] == "cid2"

        await c.delete("/api/v1/sso", headers=admin)
        assert (await c.get("/api/v1/sso", headers=admin)).json() == {"configured": False}


async def test_sso_login_flow_stubbed(monkeypatch):
    if not await _db_up():
        pytest.skip("DB not reachable")
    async with httpx.AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
        admin, org_id = await _admin_ctx(c)
        await c.put(
            "/api/v1/sso", headers=admin,
            json={"issuer": "https://idp.example.com", "clientId": "cid", "clientSecret": "sec",
                  "autoProvision": False},
        )

        # Stub the three network calls.
        async def fake_discover(issuer):
            return {
                "authorization_endpoint": "https://idp.example.com/authorize",
                "token_endpoint": "https://idp.example.com/token",
                "userinfo_endpoint": "https://idp.example.com/userinfo",
            }

        async def fake_exchange(token_endpoint, **kw):
            return {"access_token": "at-123"}

        async def fake_userinfo(endpoint, token):
            return {"email": "demo@dripstack.dev", "email_verified": True}

        monkeypatch.setattr(sso, "discover", fake_discover)
        monkeypatch.setattr(sso, "exchange_code", fake_exchange)
        monkeypatch.setattr(sso, "fetch_userinfo", fake_userinfo)

        # start → 302 to the provider with a signed state.
        start = await c.get(f"/api/v1/auth/sso/{org_id}/start")
        assert start.status_code in (302, 307)
        assert "idp.example.com/authorize" in start.headers["location"]

        state = sso._sign_state(org_id)
        cb = await c.get(f"/api/v1/auth/sso/callback?code=abc&state={state}")
        assert cb.status_code == 302
        loc = cb.headers["location"]
        # Existing demo user → tokens handed back in the fragment.
        assert "/sso/callback#" in loc and "accessToken=" in loc

        await c.delete("/api/v1/sso", headers=admin)


# ── Google sign-in (platform-level) ───────────────────────────────────────────


def test_google_state_is_not_interchangeable_with_org_state():
    """A state minted for one flow must not be replayable into the other."""
    with pytest.raises(HTTPException):
        sso._verify_google_state(sso._sign_state("org-123"))
    with pytest.raises(HTTPException):
        sso._verify_state(sso._sign_google_state())

    sso._verify_google_state(sso._sign_google_state())  # its own state is fine


def test_google_hidden_when_unconfigured(monkeypatch):
    from dripstack.config import Settings

    monkeypatch.setattr(sso, "settings", lambda: Settings(GOOGLE_CLIENT_ID=None, GOOGLE_CLIENT_SECRET=None))
    assert sso._google_configured() is False

    monkeypatch.setattr(sso, "settings", lambda: Settings(GOOGLE_CLIENT_ID="cid", GOOGLE_CLIENT_SECRET="sec"))
    assert sso._google_configured() is True


def _google_settings(**over):
    from dripstack.config import Settings

    return Settings(GOOGLE_CLIENT_ID="cid", GOOGLE_CLIENT_SECRET="sec", **over)


def _stub_google(monkeypatch, email: str, verified: bool = True):
    async def fake_discover(issuer):
        assert issuer == "https://accounts.google.com"
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


async def test_google_providers_and_start(monkeypatch):
    if not await _db_up():
        pytest.skip("DB not reachable")
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "cid")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "sec")
    from dripstack.config import settings as real_settings

    real_settings.cache_clear()
    _stub_google(monkeypatch, "demo@dripstack.dev")
    try:
        async with httpx.AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
            # `signup` rides along on this endpoint too; assert the field we care
            # about rather than the whole dict, so adding another provider flag
            # later does not break this test.
            assert (await c.get("/api/v1/auth/providers")).json()["google"] is True

            start = await c.get("/api/v1/auth/google/start")
            assert start.status_code in (302, 307)
            loc = start.headers["location"]
            assert "accounts.google.com/o/oauth2" in loc and "client_id=cid" in loc
            assert "scope=openid+email+profile" in loc
    finally:
        real_settings.cache_clear()


async def test_google_callback_known_user_and_stranger(monkeypatch):
    if not await _db_up():
        pytest.skip("DB not reachable")
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "cid")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "sec")
    from dripstack.config import settings as real_settings

    real_settings.cache_clear()
    try:
        async with httpx.AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
            state = sso._sign_google_state()

            # Seeded user → tokens in the fragment.
            _stub_google(monkeypatch, "demo@dripstack.dev")
            ok = await c.get(f"/api/v1/auth/google/callback?code=abc&state={state}")
            assert ok.status_code == 302
            assert "/sso/callback#" in ok.headers["location"] and "accessToken=" in ok.headers["location"]

            # Unknown Google account → rejected, never provisioned.
            _stub_google(monkeypatch, "stranger@gmail.com")
            no = await c.get(f"/api/v1/auth/google/callback?code=abc&state={sso._sign_google_state()}")
            assert no.status_code == 302 and "sso_error=no_account" in no.headers["location"]

            # Unverified email → rejected even if the account exists.
            _stub_google(monkeypatch, "demo@dripstack.dev", verified=False)
            unv = await c.get(f"/api/v1/auth/google/callback?code=abc&state={sso._sign_google_state()}")
            assert unv.status_code == 302 and "sso_error=email_not_verified" in unv.headers["location"]

            # Forged state → 400 before any network call.
            bad = await c.get("/api/v1/auth/google/callback?code=abc&state=not-a-jwt")
            assert bad.status_code == 400
    finally:
        real_settings.cache_clear()


async def test_sso_discover_maps_domain_to_org(monkeypatch):
    if not await _db_up():
        pytest.skip("DB not reachable")
    async with httpx.AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
        admin, org_id = await _admin_ctx(c)
        await c.put(
            "/api/v1/sso", headers=admin,
            json={"issuer": "https://idp.example.com", "clientId": "cid", "clientSecret": "sec",
                  "allowedDomain": "dripstack.dev"},
        )
        try:
            hit = await c.post("/api/v1/auth/sso/discover", json={"email": "someone@dripstack.dev"})
            assert hit.status_code == 200 and hit.json()["orgId"] == org_id

            miss = await c.post("/api/v1/auth/sso/discover", json={"email": "someone@nowhere.com"})
            assert miss.status_code == 404

            malformed = await c.post("/api/v1/auth/sso/discover", json={"email": "not-an-email"})
            assert malformed.status_code == 400
        finally:
            await c.delete("/api/v1/sso", headers=admin)


async def test_sso_resolve_rejects_unprovisioned(monkeypatch):
    if not await _db_up():
        pytest.skip("DB not reachable")
    async with session_scope() as session:
        # auto_provision off + unknown email → 403.
        conn = SimpleNamespace(
            organization_id="nonexistent-org", allowed_domain=None, auto_provision=False, default_role_slug="customer-member"
        )
        with pytest.raises(HTTPException) as exc:
            await sso.resolve_sso_user(session, conn, "stranger@nowhere.com")
        assert exc.value.status_code == 403
