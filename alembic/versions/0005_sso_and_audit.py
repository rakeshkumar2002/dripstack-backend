"""SSO connections + audit log.

Idempotent (same approach as 0002/0003/0004): on a FRESH database the current
metadata already builds `SsoConnection` and `AuditLog` via create_all, so this
revision detects each and skips; on an EXISTING database it creates them.

Revision ID: 0005_sso_and_audit
Revises: 0004_channel_integrations
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op
from dripstack.db.models import AuditLog, Base, SsoConnection

revision = "0005_sso_and_audit"
down_revision = "0004_channel_integrations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    existing = set(insp.get_table_names())
    to_create = [
        model.__table__
        for model in (SsoConnection, AuditLog)
        if model.__tablename__ not in existing
    ]
    if to_create:
        Base.metadata.create_all(bind=bind, tables=to_create, checkfirst=True)


def downgrade() -> None:
    op.drop_table("AuditLog")
    op.drop_table("SsoConnection")
