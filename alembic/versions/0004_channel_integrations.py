"""Channel integrations: per-org Slack/Teams webhook credentials

Idempotent (same approach as 0002/0003): on a FRESH database the current
metadata already builds `ChannelIntegration` via create_all, so this revision
detects it and skips; on an EXISTING database it creates the table.

Revision ID: 0004_channel_integrations
Revises: 0003_user_hardening
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op
from dripstack.db.models import Base, ChannelIntegration

revision = "0004_channel_integrations"
down_revision = "0003_user_hardening"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if ChannelIntegration.__tablename__ not in set(insp.get_table_names()):
        Base.metadata.create_all(bind=bind, tables=[ChannelIntegration.__table__], checkfirst=True)


def downgrade() -> None:
    op.drop_table("ChannelIntegration")
