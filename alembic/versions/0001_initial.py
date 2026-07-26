"""initial schema — all DripStack tables + enums

Creates the full schema directly from the SQLAlchemy models (single source of
truth), which keeps migrations and ORM in lockstep for this greenfield DB.

Revision ID: 0001_initial
Revises:
"""

from __future__ import annotations

from alembic import op
from dripstack.db.models import Base

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    Base.metadata.create_all(bind=op.get_bind())


def downgrade() -> None:
    Base.metadata.drop_all(bind=op.get_bind())
