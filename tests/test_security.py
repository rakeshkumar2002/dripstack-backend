"""Security hardening: production secret guard, security headers, the action
confirmation interstitial (anti-prefetch/CSRF), and open-redirect binding."""

from __future__ import annotations

import httpx
import pytest
from httpx import ASGITransport

from dripstack.config import Settings, assert_production_secrets
from dripstack.shared.crypto import sign_link_token, verify_link_token

# ── Production secret guard ───────────────────────────────────────────────────


def test_secret_guard_noop_in_development():
    s = Settings(NODE_ENV="development")
    assert_production_secrets(s)  # must not raise


def test_secret_guard_blocks_default_secrets_in_production():
    s = Settings(NODE_ENV="production", DATABASE_URL="postgresql://x/y")
    with pytest.raises(RuntimeError) as exc:
        assert_production_secrets(s)
    msg = str(exc.value)
    assert "JWT_ACCESS_SECRET" in msg and "LINK_SIGNING_SECRET" in msg


def test_secret_guard_blocks_short_secrets():
    s = Settings(
        NODE_ENV="production",
        DATABASE_URL="postgresql://x/y",
        JWT_ACCESS_SECRET="short",
        JWT_REFRESH_SECRET="short",
        LINK_SIGNING_SECRET="short",
    )
    with pytest.raises(RuntimeError) as exc:
        assert_production_secrets(s)
    assert "at least 32 chars" in str(exc.value)


def _prod_settings(**overrides) -> Settings:
    """A production Settings that passes every guard, minus any overrides."""
    base = dict(
        NODE_ENV="production",
        DATABASE_URL="postgresql://x/y",
        JWT_ACCESS_SECRET="a" * 40,
        JWT_REFRESH_SECRET="b" * 40,
        LINK_SIGNING_SECRET="c" * 40,
        APP_BASE_URL="https://api.example.com",
        DASHBOARD_URL="https://console.example.com",
    )
    base.update(overrides)
    return Settings(**base)


def test_secret_guard_passes_with_strong_secrets():
    assert_production_secrets(_prod_settings())  # must not raise


# ── Production URL guard ──────────────────────────────────────────────────────
# A prod boot with default URLs used to succeed, then 403 every browser request
# (CORS origin mismatch) and mail un-clickable localhost tracked links.


def test_prod_guard_rejects_localhost_dashboard_url():
    with pytest.raises(RuntimeError) as exc:
        assert_production_secrets(_prod_settings(DASHBOARD_URL="http://localhost:3000"))
    assert "still points at localhost" in str(exc.value)


def test_prod_guard_rejects_non_https_app_base_url():
    with pytest.raises(RuntimeError) as exc:
        assert_production_secrets(_prod_settings(APP_BASE_URL="http://api.example.com"))
    assert "must be an https:// URL" in str(exc.value)


def test_prod_guard_rejects_trailing_slash():
    # Invisible everywhere except CORS, where it 403s every browser request.
    with pytest.raises(RuntimeError) as exc:
        assert_production_secrets(_prod_settings(DASHBOARD_URL="https://console.example.com/"))
    assert "must not end in '/'" in str(exc.value)


def test_prod_guard_is_noop_outside_production():
    assert_production_secrets(Settings(NODE_ENV="development"))  # must not raise


# ── CORS origin list ──────────────────────────────────────────────────────────


def test_cors_origins_strips_trailing_slash_and_dedupes():
    s = Settings(
        DASHBOARD_URL="https://console.example.com/",
        CORS_ALLOWED_ORIGINS="https://preview.example.com/, https://console.example.com , ",
    )
    assert s.cors_origins == ["https://console.example.com", "https://preview.example.com"]


def test_cors_origins_defaults_to_dashboard_url_only():
    assert Settings(DASHBOARD_URL="https://console.example.com").cors_origins == [
        "https://console.example.com"
    ]


# ── Link token binding (open-redirect prevention) ─────────────────────────────


def test_link_token_binds_destination_url():
    secret = "s"
    url = "https://example.com/docs"
    tok = sign_link_token(secret, "run1", "link", "ref1", extra=url)
    assert verify_link_token(secret, "run1", "link", "ref1", tok, extra=url)
    # Same token must NOT verify for a different destination.
    assert not verify_link_token(secret, "run1", "link", "ref1", tok, extra="https://evil.com")


def test_action_token_unaffected_by_extra_default():
    secret = "s"
    tok = sign_link_token(secret, "run1", "action", "resolve")
    assert verify_link_token(secret, "run1", "action", "resolve", tok)


# ── App-level: headers + interstitial (no DB needed for these paths) ──────────


def _app():
    from dripstack.api.main import create_app

    return create_app()


async def test_security_headers_present():
    async with httpx.AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
        r = await c.get("/health")
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["x-frame-options"] == "DENY"
        assert "referrer-policy" in r.headers


async def test_action_get_shows_confirmation_not_mutation():
    """A GET (what scanners/prefetch issue) must render a confirm form, never act."""
    from urllib.parse import urlsplit

    from dripstack.links import make_link_builder

    url = make_link_builder("run-xyz").action_url("resolve")
    parts = urlsplit(url)
    path = f"{parts.path}?{parts.query}"
    async with httpx.AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
        r = await c.get(path)
        assert r.status_code == 200
        assert "<form" in r.text and 'method="post"' in r.text


async def test_action_rejects_bad_token():
    async with httpx.AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
        assert (await c.get("/r/run1/action/resolve?token=bad")).status_code == 403
        assert (await c.post("/r/run1/action/resolve?token=bad")).status_code == 403
        assert (await c.get("/r/run1/action/bogus?token=bad")).status_code == 400


async def test_link_rejects_unsigned_destination():
    async with httpx.AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
        # No token / tampered destination → 403, never a redirect.
        r = await c.get("/r/run1/link/ref1?u=https%3A%2F%2Fevil.com&token=bad")
        assert r.status_code == 403
