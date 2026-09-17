"""M2: ack-driven delivery, leases, durable dedup, dead-letter queue.

Revision ID: 0003
Revises: 0002
Create Date: 2026-09-20

Four defects this closes:

1. **"Delivered" did not mean delivered.** ``QueuedMessage.delivered`` was set
   the moment ``send_json`` returned - i.e. when bytes reached a socket, not
   when the agent received them. The client already sends ``delivery_ack``;
   the gateway discarded it with a ``pass``. Rows are now marked delivered only
   on ack, tracked by ``acked_at``.

2. **No crash-recovery bound.** Without a lease, a replica that died mid-send
   left a row that was already flagged delivered (lost), or one that every
   replica would retry (duplicates). ``in_flight_at`` leases a row to one
   replica for ``delivery_lease_seconds``, bounding duplicates to the crash
   window.

3. **Deduplication was per-process.** The router used an in-process ``set`` of
   relay ids: empty after every restart, and separate per replica - so the same
   message was processed once per replica. ``processed_relays`` makes dedup
   durable and shared.

4. **Undeliverable messages vanished.** Queue overflow deleted the oldest rows
   and TTL cleanup deleted expired-undelivered rows, both without a trace.
   ``dead_letter_messages`` records them with a reason for diagnosis.

Also adds ``max_delivery_attempts``-style accounting via the existing
``delivery_attempts`` column (now incremented at claim time, so a poison
recipient that keeps accepting connections but never acks is eventually
dead-lettered instead of retried for ever).
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _columns(inspector, table: str) -> set[str]:
    return {c["name"] for c in inspector.get_columns(table)}


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    # --- queued_messages: ack + lease + claim columns ---------------------
    if "queued_messages" in tables:
        cols = _columns(inspector, "queued_messages")
        for name, column in (
            ("acked_at", sa.Column("acked_at", sa.DateTime(timezone=True), nullable=True)),
            (
                "in_flight_at",
                sa.Column("in_flight_at", sa.DateTime(timezone=True), nullable=True),
            ),
            ("claimed_by", sa.Column("claimed_by", sa.String(64), nullable=True)),
        ):
            if name not in cols:
                op.add_column("queued_messages", column)

        index_names = {
            i["name"] for i in inspector.get_indexes("queued_messages")
        }
        if "ix_queued_messages_pending" not in index_names:
            op.create_index(
                "ix_queued_messages_pending",
                "queued_messages",
                ["recipient_id", "delivered", "created_at"],
            )

    # --- processed_relays: durable, cross-replica dedup -------------------
    if "processed_relays" not in tables:
        op.create_table(
            "processed_relays",
            sa.Column("relay_id", sa.String(128), primary_key=True),
            sa.Column("sender_id", sa.String(64), nullable=False),
            sa.Column("recipient_id", sa.String(64), nullable=False),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.func.now(),
                nullable=False,
            ),
        )
        op.create_index(
            "ix_processed_relays_created", "processed_relays", ["created_at"]
        )

    # --- dead_letter_messages --------------------------------------------
    if "dead_letter_messages" not in tables:
        op.create_table(
            "dead_letter_messages",
            sa.Column(
                "id",
                postgresql.UUID(as_uuid=True),
                server_default=sa.text("gen_random_uuid()"),
                primary_key=True,
            ),
            sa.Column("relay_id", sa.String(128), nullable=False),
            sa.Column("sender_id", sa.String(64), nullable=False),
            sa.Column("recipient_id", sa.String(64), nullable=False),
            sa.Column(
                "envelope_json",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=True,
            ),
            sa.Column("reason", sa.String(64), nullable=False),
            sa.Column("detail", sa.Text(), nullable=True),
            sa.Column(
                "delivery_attempts",
                sa.Integer(),
                server_default=sa.text("0"),
                nullable=False,
            ),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.func.now(),
                nullable=False,
            ),
        )
        op.create_index(
            "ix_dead_letter_recipient", "dead_letter_messages", ["recipient_id"]
        )

    # --- delivery_log retention index ------------------------------------
    if "delivery_log" in tables:
        index_names = {i["name"] for i in inspector.get_indexes("delivery_log")}
        if "ix_delivery_log_created" not in index_names:
            op.create_index(
                "ix_delivery_log_created", "delivery_log", ["created_at"]
            )


def downgrade() -> None:
    op.drop_index("ix_delivery_log_created", table_name="delivery_log")
    op.drop_index("ix_dead_letter_recipient", table_name="dead_letter_messages")
    op.drop_table("dead_letter_messages")
    op.drop_index("ix_processed_relays_created", table_name="processed_relays")
    op.drop_table("processed_relays")
    op.drop_index("ix_queued_messages_pending", table_name="queued_messages")
    op.drop_column("queued_messages", "claimed_by")
    op.drop_column("queued_messages", "in_flight_at")
    op.drop_column("queued_messages", "acked_at")
