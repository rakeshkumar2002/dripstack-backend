import pytest
from fastapi import HTTPException

from dripstack.api.auth import Principal, require_permission, require_platform
from dripstack.permissions import ALL_KEYS, SYSTEM_ROLES


def _principal(perms, scope="organization", platform=False):
    return Principal(
        user_id="u",
        organization_id="o",
        role_slug="r",
        scope=scope,
        is_platform=platform,
        permissions=set(perms),
    )


def test_integration_admin_has_every_permission():
    assert set(SYSTEM_ROLES["integration-admin"]["permissions"]) == set(ALL_KEYS)


def test_customer_admin_excludes_customer_management():
    perms = SYSTEM_ROLES["customer-admin"]["permissions"]
    assert not any(p.startswith("customers.") for p in perms)
    assert "users.write" in perms
    assert "technicians.write" in perms
    assert "email.write" in perms


def test_customer_member_is_read_only_subset():
    perms = set(SYSTEM_ROLES["customer-member"]["permissions"])
    assert perms == {"technicians.read", "sequences.read", "integrations.read", "analytics.read"}
    assert "technicians.write" not in perms


async def test_require_permission_allows_and_blocks():
    dep = require_permission("users.write")
    ok = _principal({"users.write"})
    assert await dep(ok) is ok
    with pytest.raises(HTTPException) as exc:
        await dep(_principal(set()))
    assert exc.value.status_code == 403


async def test_require_platform_blocks_org_users():
    platform = _principal(set(), scope="platform", platform=True)
    assert await require_platform(platform) is platform
    with pytest.raises(HTTPException) as exc:
        await require_platform(_principal(set(), scope="organization"))
    assert exc.value.status_code == 403


async def test_org_admin_can_patch_settings():
    """Regression: PATCH /settings used `auth.role != "admin"`, but
    auth_context_for() puts the RBAC *slug* in ctx.role — so every normally
    created customer-admin got a 403 and org settings were uneditable."""
    import httpx
    from httpx import ASGITransport
    from sqlalchemy import text

    from dripstack.db.session import session_scope

    try:
        async with session_scope() as s:
            await s.execute(text("SELECT 1"))
    except Exception:  # noqa: BLE001
        pytest.skip("DB not reachable")

    from dripstack.api.main import create_app

    async with httpx.AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:
        tok = (
            await c.post(
                "/api/v1/auth/login",
                json={"email": "demo@dripstack.dev", "password": "DripStackDemo!23"},
            )
        ).json()["accessToken"]
        headers = {"authorization": f"Bearer {tok}"}

        before = (await c.get("/api/v1/settings", headers=headers)).json()["organization"]
        original = before.get("settings") or {}

        r = await c.patch("/api/v1/settings", headers=headers, json={"settings": {**original, "qaProbe": True}})
        assert r.status_code == 200, r.text
        assert r.json()["organization"]["settings"]["qaProbe"] is True

        # Put it back so the demo org is unchanged.
        await c.patch("/api/v1/settings", headers=headers, json={"settings": original})
