"""User hardening: is_active column + global-unique email

Idempotent (same approach as 0002): on a FRESH database the current metadata
already has `User.is_active` and the global `User_email_key` constraint, so this
revision detects that and skips. On an EXISTING database it adds the column and
swaps the per-org email constraint (`User_org_email_key`) for a global one.

Revision ID: 0003_user_hardening
Revises: 0002_rbac
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0003_user_hardening"
down_revision = "0002_rbac"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)

    user_cols = {c["name"] for c in insp.get_columns("User")}
    if "is_active" not in user_cols:
        op.add_column(
            "User",
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        )

    uniques = {uc["name"] for uc in insp.get_unique_constraints("User")}
    if "User_email_key" not in uniques:
        if "User_org_email_key" in uniques:
            op.drop_constraint("User_org_email_key", "User", type_="unique")
        op.create_unique_constraint("User_email_key", "User", ["email"])


def downgrade() -> None:
    op.drop_constraint("User_email_key", "User", type_="unique")
    op.create_unique_constraint("User_org_email_key", "User", ["organization_id", "email"])
    op.drop_column("User", "is_active")
