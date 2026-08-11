"""Regressions for the three findings from the security review:

1. login had no rate limit (credential stuffing)
2. customer-supplied URLs were fetched server-side with no SSRF guard
3. refresh re-minted old claims without re-checking the account
"""

from __future__ import annotations

import httpx
import pytest
from httpx import ASGITransport
from sqlalchemy import select, text

from dripstack.db import User
from dripstack.db.session import session_scope
from dripstack.shared import UnsafeUrlError, assert_safe_outbound_url


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


async def _login(c, email="demo@dripstack.dev", password="DripStackDemo!23"):
    return (await c.post("/api/v1/auth/login", json={"email": email, "password": password})).json()


# ── 2 · SSRF guard (pure, no DB) ──────────────────────────────────────────────


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1/hook",           # loopback
        "https://localhost/hook",           # loopback by name
        "https://169.254.169.254/latest/",  # cloud metadata
        "https://10.0.0.5/hook",            # RFC1918
        "https://192.168.1.10/hook",
        "https://172.16.0.9/hook",
        "https://[::1]/hook",               # loopback v6
    ],
)
def test_internal_targets_are_refused(url):
    with pytest.raises(UnsafeUrlError):
        assert_safe_outbound_url(url)


@pytest.mark.parametrize("url", ["http://example.com/hook", "ftp://example.com", "file:///etc/passwd", "https:///nohost"])
def test_bad_schemes_and_missing_host_refused(url):
    with pytest.raises(UnsafeUrlError):
        assert_safe_outbound_url(url)


def test_plain_http_allowed_only_when_asked():
    with pytest.raises(UnsafeUrlError):
        assert_safe_outbound_url("http://example.com/hook")
    assert_safe_outbound_url("http://example.com/hook", require_https=False)  # no raise


def test_public_url_passes():
    assert_safe_outbound_url("https://example.com/hook")  # no raise


def test_unresolvable_host_is_allowed_at_config_time():
    """It cannot be an SSRF target, and a transient DNS failure must not block
    saving a legitimate URL. Rebinding is caught by the fetch-time checks."""
    assert_safe_outbound_url("https://nx-does-not-exist.invalid/hook")  # no raise


# ── 2 · …enforced at the API boundary ─────────────────────────────────────────


async def test_outbound_webhook_rejects_internal_url():
    if not await _db_up():
        pytest.skip("DB not reachable")
    async with httpx.AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
        tok = (await _login(c))["accessToken"]
        h = {"authorization": f"Bearer {tok}"}

        for bad in ("https://169.254.169.254/latest/meta-data/", "https://127.0.0.1:15672/api/whoami"):
            r = await c.post("/api/v1/outbound-webhooks", headers=h,
                             json={"url": bad, "events": ["run.resolved"]})
            assert r.status_code == 400, f"{bad} was accepted"
            assert "non-public" in r.text or "resolve" in r.text


async def test_sso_issuer_rejects_internal_url():
    if not await _db_up():
        pytest.skip("DB not reachable")
    async with httpx.AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
        tok = (await _login(c))["accessToken"]
        r = await c.put("/api/v1/sso", headers={"authorization": f"Bearer {tok}"},
                        json={"issuer": "https://127.0.0.1", "clientId": "cid", "clientSecret": "sec"})
        assert r.status_code == 400


# ── 3 · refresh honours account state ─────────────────────────────────────────


async def test_refresh_refuses_a_deactivated_user():
    if not await _db_up():
        pytest.skip("DB not reachable")
    async with httpx.AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
        tokens = await _login(c)
        refresh_token = tokens["refreshToken"]

        # Works while the account is active.
        assert (await c.post("/api/v1/auth/refresh", json={"refreshToken": refresh_token})).status_code == 200

        async with session_scope() as s:
            user = (await s.execute(select(User).where(User.email == "demo@dripstack.dev"))).scalars().first()
            user.is_active = False
        try:
            # Previously this still returned a fresh pair for the whole refresh
            # window, so suspending an account did nothing.
            r = await c.post("/api/v1/auth/refresh", json={"refreshToken": refresh_token})
            assert r.status_code == 401
        finally:
            async with session_scope() as s:
                user = (await s.execute(select(User).where(User.email == "demo@dripstack.dev"))).scalars().first()
                user.is_active = True


async def test_refresh_refuses_a_token_for_a_deleted_user():
    if not await _db_up():
        pytest.skip("DB not reachable")
    import jwt as _jwt

    from dripstack.config import settings

    forged = _jwt.encode(
        {"sub": "no-such-user", "org": "no-such-org", "role": "customer-admin",
         "scope": "organization", "plt": False, "exp": 2 ** 31},
        settings().JWT_REFRESH_SECRET, algorithm="HS256",
    )
    async with httpx.AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
        r = await c.post("/api/v1/auth/refresh", json={"refreshToken": forged})
        assert r.status_code == 401


# ── 1 · login is throttled ────────────────────────────────────────────────────


async def test_login_is_rate_limited():
    if not await _db_up():
        pytest.skip("DB not reachable")
    async with httpx.AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
        codes = []
        for _ in range(14):
            r = await c.post("/api/v1/auth/login",
                             json={"email": "demo@dripstack.dev", "password": "wrong-on-purpose"})
            codes.append(r.status_code)
        # 10/minute: wrong passwords give 401 until the limiter takes over.
        assert 429 in codes, f"login never throttled: {codes}"
        assert codes.index(429) <= 11, f"throttled later than expected: {codes}"
