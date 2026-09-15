"""
SQLAlchemy ORM models for the Nexus Gateway database.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Index, String, func, text, Boolean, Integer, DateTime
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy declarative models."""
    pass


class RegisteredAgent(Base):
    """Represents an agent registered with the gateway."""
    __tablename__ = "registered_agents"

    agent_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    public_key: Mapped[str] = mapped_column(String(128), nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), nullable=False
    )
    is_online: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class QueuedMessage(Base):
    """Represents a message queued for delivery."""
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
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_queued_messages_recipient_delivered", "recipient_id", "delivered"),
        Index("ix_queued_messages_expires_at", "expires_at"),
    )


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
    )
