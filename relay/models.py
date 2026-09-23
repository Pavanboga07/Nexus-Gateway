"""Relay Postgres models (Postgres ONLY — see tests/relay_db.py).

Tables (all shared state lives here so a second replica needs no
redesign):

- ``relay_messages``: durable outbox queue. ``message_id`` is UNIQUE —
  that constraint IS the dedup (no in-memory sets). ``status`` is one of
  ``pending`` / ``delivered`` / ``dlq`` / ``expired``.
- ``agent_directory``: verified agent cards. ``handle`` is UNIQUE when
  present — the constraint makes handle claims atomic.
- ``agent_presence``: last heartbeat per agent (``replica_id`` records
  which relay process saw it).
- ``auth_challenges``: single-use 32-byte challenges (base64 PK).
- ``rate_hits``: per-IP directory write attempts for rate limiting.
- ``relay_invites``: single-use invite claims (token hash -> card).
- ``invite_claim_attempts``: per-IP wrong-code attempts for cooldown.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class RelayMessage(Base):
    __tablename__ = "relay_messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    message_id: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    sender: Mapped[str] = mapped_column(Text, nullable=False)
    recipient: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    envelope: Mapped[dict] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="pending", index=True
    )
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    delivered_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_attempt_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class DirectoryEntry(Base):
    __tablename__ = "agent_directory"

    agent_id: Mapped[str] = mapped_column(Text, primary_key=True)
    handle: Mapped[str | None] = mapped_column(Text, unique=True, nullable=True)
    public_key: Mapped[str] = mapped_column(Text, nullable=False)
    display_name: Mapped[str] = mapped_column(Text, nullable=False)
    card: Mapped[dict] = mapped_column(JSONB, nullable=False)
    signature: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class Presence(Base):
    __tablename__ = "agent_presence"

    agent_id: Mapped[str] = mapped_column(Text, primary_key=True)
    replica_id: Mapped[str] = mapped_column(Text, nullable=False, default="")
    display_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_heartbeat: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class Challenge(Base):
    __tablename__ = "auth_challenges"

    challenge: Mapped[str] = mapped_column(Text, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    used: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    agent_id: Mapped[str | None] = mapped_column(Text, nullable=True)


class RateHit(Base):
    __tablename__ = "rate_hits"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ip: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class Invite(Base):
    __tablename__ = "relay_invites"

    token_hash: Mapped[str] = mapped_column(Text, primary_key=True)
    agent_id: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    card: Mapped[dict] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    used: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class ClaimAttempt(Base):
    __tablename__ = "invite_claim_attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ip: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


TABLE_NAMES = [
    "relay_messages",
    "agent_directory",
    "agent_presence",
    "auth_challenges",
    "rate_hits",
    "relay_invites",
    "invite_claim_attempts",
]

__all__ = [
    "TABLE_NAMES",
    "Base",
    "Challenge",
    "ClaimAttempt",
    "DirectoryEntry",
    "Invite",
    "Presence",
    "RateHit",
    "RelayMessage",
]
