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
