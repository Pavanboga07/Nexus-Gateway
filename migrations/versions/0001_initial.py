"""0001_initial: Initial schema for Nexus Gateway

Revision ID: 0001
Revises:
Create Date: 2026-09-15 10:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "registered_agents",
        sa.Column("agent_id", sa.String(64), primary_key=True),
        sa.Column("public_key", sa.String(128), nullable=False),
        sa.Column("display_name", sa.String(128), nullable=True),
        sa.Column(
            "first_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "is_online",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
    )

    op.create_table(
        "queued_messages",
        sa.Column("relay_id", sa.String(128), primary_key=True),
        sa.Column("sender_id", sa.String(64), nullable=False),
        sa.Column("recipient_id", sa.String(64), nullable=False),
        sa.Column("envelope_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "delivered",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column(
            "delivery_attempts",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "idx_queued_recipient",
        "queued_messages",
        ["recipient_id", "delivered"],
    )
    op.create_index(
        "idx_queued_expires",
        "queued_messages",
        ["expires_at"],
    )

    op.create_table(
        "delivery_log",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            primary_key=True,
        ),
        sa.Column("relay_id", sa.String(128), nullable=False),
        sa.Column("sender_id", sa.String(64), nullable=False),
        sa.Column("recipient_id", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "idx_delivery_log_relay",
        "delivery_log",
        ["relay_id"],
    )


def downgrade() -> None:
    op.drop_index("idx_delivery_log_relay", table_name="delivery_log")
    op.drop_table("delivery_log")
    op.drop_index("idx_queued_expires", table_name="queued_messages")
    op.drop_index("idx_queued_recipient", table_name="queued_messages")
    op.drop_table("queued_messages")
    op.drop_table("registered_agents")
