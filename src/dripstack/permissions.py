"""Canonical RBAC permissions, categories, and system roles.

`Permission.category` (one of PermissionCategory) groups the keys into the three
categories the product manages: who can manage users, who can manage customer
organizations, and who can configure the app. The seed loads these into the
Permission / Role / RolePermission tables.
"""

from __future__ import annotations

from .db.models import PermissionCategory, RoleScope

# (key, category, description)
PERMISSIONS: list[tuple[str, PermissionCategory, str]] = [
    # user_management
    ("users.read", PermissionCategory.user_management, "View users"),
    ("users.write", PermissionCategory.user_management, "Create / edit users + assign roles"),
    ("users.delete", PermissionCategory.user_management, "Delete users"),
    # customer_management (platform tier)
    ("customers.read", PermissionCategory.customer_management, "View customer organizations"),
    ("customers.write", PermissionCategory.customer_management, "Create / configure customers + credentials"),
    ("customers.delete", PermissionCategory.customer_management, "Delete customer organizations"),
    # configuration
    ("technicians.read", PermissionCategory.configuration, "View technicians"),
    ("technicians.write", PermissionCategory.configuration, "Manage technician contacts + emails"),
    ("sequences.read", PermissionCategory.configuration, "View sequences"),
    ("sequences.write", PermissionCategory.configuration, "Edit sequences"),
    ("integrations.read", PermissionCategory.configuration, "View integrations"),
    ("integrations.write", PermissionCategory.configuration, "Manage integrations"),
    ("analytics.read", PermissionCategory.configuration, "View analytics + pipeline"),
    ("email.write", PermissionCategory.configuration, "Configure email / ESP settings"),
]

ALL_KEYS = [p[0] for p in PERMISSIONS]


def _keys(*prefixes: str) -> list[str]:
    return [k for k in ALL_KEYS if any(k.startswith(p) for p in prefixes)]


# slug -> {name, scope, permission keys}
SYSTEM_ROLES: dict[str, dict] = {
    "integration-admin": {
        "name": "Integration Admin",
        "scope": RoleScope.platform,
        "permissions": ALL_KEYS,  # full platform access
    },
    "customer-admin": {
        "name": "Customer Admin",
        "scope": RoleScope.organization,
        # everything except customer_management (platform-only)
        "permissions": _keys("users.", "technicians.", "sequences.", "integrations.", "analytics.", "email."),
    },
    "customer-member": {
        "name": "Customer Member",
        "scope": RoleScope.organization,
        "permissions": ["technicians.read", "sequences.read", "integrations.read", "analytics.read"],
    },
}
