"""V3 pairing invites: relay_invites + invite_claim_attempts.

Revision ID: 0002
Revises: 0001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "relay_invites",
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column("agent_id", sa.Text(), nullable=False),
        sa.Column("card", JSONB, nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True),
            server_default=sa.func.now(), nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used", sa.Boolean(), nullable=False, default=False),
        sa.Column("attempts", sa.Integer(), nullable=False, default=0),
        sa.PrimaryKeyConstraint("token_hash"),
    )
    op.create_index(
        "ix_relay_invites_agent_id", "relay_invites", ["agent_id"]
    )
    op.create_table(
        "invite_claim_attempts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("ip", sa.Text(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True),
            server_default=sa.func.now(), nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_invite_claim_attempts_ip", "invite_claim_attempts", ["ip"]
    )


def downgrade() -> None:
    op.drop_index("ix_invite_claim_attempts_ip")
    op.drop_table("invite_claim_attempts")
    op.drop_index("ix_relay_invites_agent_id")
    op.drop_table("relay_invites")
