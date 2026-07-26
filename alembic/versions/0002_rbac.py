"""RBAC: permissions, roles, role-permissions + user/contact columns

Idempotent: the baseline 0001 migration uses Base.metadata.create_all, so on a
FRESH database the RBAC tables/columns already exist (current metadata) and this
revision skips them; on an EXISTING database (migrated before RBAC) it adds the
missing tables + columns. Safe to run either way.

Revision ID: 0002_rbac
Revises: 0001_initial
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op
from dripstack.db.models import Base, Permission, RbacRole, RolePermission

revision = "0002_rbac"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    existing = set(insp.get_table_names())

    new_tables = [
        t.__table__
        for t in (Permission, RbacRole, RolePermission)
        if t.__tablename__ not in existing
    ]
    if new_tables:
        # create_all(checkfirst) also creates the backing PG enum types as needed.
        Base.metadata.create_all(bind=bind, tables=new_tables, checkfirst=True)

    user_cols = {c["name"] for c in insp.get_columns("User")}
    if "role_id" not in user_cols:
        op.add_column(
            "User",
            sa.Column("role_id", sa.String(), sa.ForeignKey("Role_rbac.id", ondelete="SET NULL"), nullable=True),
        )
    if "is_platform_staff" not in user_cols:
        op.add_column(
            "User",
            sa.Column("is_platform_staff", sa.Boolean(), nullable=False, server_default=sa.false()),
        )

    contact_cols = {c["name"] for c in insp.get_columns("Contact")}
    if "title" not in contact_cols:
        op.add_column("Contact", sa.Column("title", sa.String(), nullable=True))
    if "active" not in contact_cols:
        op.add_column("Contact", sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()))


def downgrade() -> None:
    for col in ("role_id", "is_platform_staff"):
        op.drop_column("User", col)
    for col in ("title", "active"):
        op.drop_column("Contact", col)
    op.drop_table("RolePermission")
    op.drop_table("Role_rbac")
    op.drop_table("Permission")
