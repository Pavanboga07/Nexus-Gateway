"""Initial relay schema: queue, dedup, directory, presence, challenges.

Revision ID: 0001
Revises: (none)
"""

from __future__ import annotations

from alembic import op
from relay.models import Base

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    Base.metadata.create_all(bind=op.get_bind())


def downgrade() -> None:
    Base.metadata.drop_all(bind=op.get_bind())
