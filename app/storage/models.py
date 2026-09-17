"""
SQLAlchemy ORM models for the Nexus Gateway database.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Index, String, func, text, Boolean, Integer, DateTime, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy declarative models."""
    pass


#: Handles are unique per NON-NULL value only. A partial unique index lets
#: ``INSERT ... ON CONFLICT (handle)`` arbitrate handle claims atomically
#: while still allowing many agents to have no handle at all. The previous
#: full unique index made ``handle`` impossible to use as a conflict target
#: for an insert that also collides on the ``agent_id`` primary key.
HANDLE_UNIQUE_INDEX = "uq_registered_agents_handle"


class RegisteredAgent(Base):
    """Represents an agent registered with the gateway."""
    __tablename__ = "registered_agents"

    agent_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    public_key: Mapped[str] = mapped_column(String(128), nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    handle: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), nullable=False
    )
    is_online: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    agent_card: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    __table_args__ = (
        Index(
            HANDLE_UNIQUE_INDEX,
            "handle",
            unique=True,
            postgresql_where=text("handle IS NOT NULL"),
        ),
    )


class QueuedMessage(Base):
    """An outbox row: one message awaiting delivery to one recipient.

    Delivery semantics (M2)
    -----------------------
    A row is NOT delivered when the gateway writes bytes to a socket. It is
    delivered when the recipient's client sends a ``delivery_ack``. That
    distinction is the whole point of this table:

        * ``delivered``      set only on ack (or on ack-less direct delivery)
        * ``acked_at``       when the recipient confirmed receipt
        * ``in_flight_at``   lease timestamp: a send is in progress for this
                             row. Another replica must not pick it up until the
                             lease expires, which bounds duplicate delivery to
                             the crash window instead of allowing it always.
        * ``delivery_attempts`` counts sends, so poison messages can be routed
                             to the dead-letter queue instead of retried for ever.
        * ``expires_at``     hard TTL; expired rows are dropped, not delivered.
    """

    __tablename__ = "queued_messages"

    relay_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    sender_id: Mapped[str] = mapped_column(String(64), nullable=False)
    recipient_id: Mapped[str] = mapped_column(String(64), nullable=False)
    envelope_json: Mapped[dict] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    delivered: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    delivery_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    delivered_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    #: Set when the recipient acks receipt.
    acked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    #: Lease held while a send is in flight (crash-recovery bound).
    in_flight_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    #: Replica that last claimed the row (diagnostics / debugging).
    claimed_by: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        Index("ix_queued_messages_recipient_delivered", "recipient_id", "delivered"),
        Index("ix_queued_messages_expires_at", "expires_at"),
        # Supports the claim query: pending rows for a recipient, oldest first.
        Index(
            "ix_queued_messages_pending",
            "recipient_id",
            "delivered",
            "created_at",
        ),
    )


class DeadLetterMessage(Base):
    """A message the gateway gave up on, with the reason.

    Poison messages (a recipient that keeps accepting a connection but never
    acking, or repeated send failures) must not be retried for ever, and must
    not silently vanish either. They land here with enough context to diagnose
    and, if desired, replay.
    """

    __tablename__ = "dead_letter_messages"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    relay_id: Mapped[str] = mapped_column(String(128), nullable=False)
    sender_id: Mapped[str] = mapped_column(String(64), nullable=False)
    recipient_id: Mapped[str] = mapped_column(String(64), nullable=False)
    envelope_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    reason: Mapped[str] = mapped_column(String(64), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    delivery_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), nullable=False
    )

    __table_args__ = (Index("ix_dead_letter_recipient", "recipient_id"),)


class ProcessedRelay(Base):
    """Relay-id deduplication that survives restarts and spans replicas.

    The router previously deduplicated in an in-process ``set``. That means the
    set was empty after every restart and, worse, EACH replica had its own set -
    so the same relay_id was processed once per replica, producing duplicate
    deliveries precisely when horizontal scaling was attempted.
    """

    __tablename__ = "processed_relays"

    relay_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    sender_id: Mapped[str] = mapped_column(String(64), nullable=False)
    recipient_id: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), nullable=False
    )

    __table_args__ = (Index("ix_processed_relays_created", "created_at"),)


class DeliveryLog(Base):
    """Log of message delivery attempts."""

    __tablename__ = "delivery_log"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    relay_id: Mapped[str] = mapped_column(String(128), nullable=False)
    sender_id: Mapped[str] = mapped_column(String(64), nullable=False)
    recipient_id: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), nullable=False
    )

    __table_args__ = (
        Index("ix_delivery_log_relay_id", "relay_id"),
        Index("ix_delivery_log_created", "created_at"),
    )
