"""Durable outbox queue (Postgres, at-least-once).

Semantics (redesign spec, section 2):

- offline messages persist with TTL; rows stay ``pending`` until the
  recipient's ``delivery_ack`` — "delivered" means acked, never
  bytes-on-socket;
- attempts are counted on every claim; rows move to ``dlq`` after
  ``max_attempts`` unacked claims;
- expired rows are swept to ``expired`` and never delivered;
- ``enqueue`` is idempotent on ``message_id`` (UNIQUE constraint — the
  dedup; no in-memory sets): a repeat returns ``dedup_hit`` and causes
  no redelivery;
- claims use ``SELECT ... FOR UPDATE SKIP LOCKED`` so concurrent
  workers/replicas never take the same row;
- a full per-recipient queue moves the oldest rows to ``dlq`` with a
  count the caller can meter (never a silent drop).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from relay.envelope import parse_iso
from relay.models import RelayMessage

MAX_ATTEMPTS_DEFAULT = 5
MAX_PER_RECIPIENT_DEFAULT = 1000
CLAIM_LIMIT_DEFAULT = 50


def _row_to_dict(row: RelayMessage) -> dict[str, Any]:
    return {
        "message_id": row.message_id,
        "sender": row.sender,
        "recipient": row.recipient,
        "envelope": dict(row.envelope),
        "attempts": row.attempts,
        "status": row.status,
    }


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


async def enqueue(
    session: AsyncSession,
    *,
    envelope: dict[str, Any],
    max_per_recipient: int = MAX_PER_RECIPIENT_DEFAULT,
) -> str:
    """Store an envelope; ``"queued"`` or ``"dedup_hit"``.

    Requires ``message_id`` / ``sender`` / ``recipient`` / ``expires_at``
    (strict UTC). Full envelope validation happens at the socket edge;
    this is the persistence contract.
    """
    try:
        message_id = envelope["message_id"]
        sender = envelope["sender"]
        recipient = envelope["recipient"]
        expires_at = _as_utc(parse_iso(envelope["expires_at"]))
    except KeyError as exc:
        raise ValueError(f"envelope is missing {exc}") from exc
    stmt = (
        pg_insert(RelayMessage)
        .values(
            message_id=message_id,
            sender=sender,
            recipient=recipient,
            envelope=dict(envelope),
            status="pending",
            expires_at=expires_at,
        )
        .on_conflict_do_nothing(index_elements=["message_id"])
        .returning(RelayMessage.id)
    )
    inserted = (await session.execute(stmt)).scalar_one_or_none()
    await session.flush()
    if inserted is None:
        return "dedup_hit"
    # Per-recipient cap: oldest excess pending rows go to DLQ (metered).
    pending_ids = (
        await session.execute(
            select(RelayMessage.id)
            .where(
                RelayMessage.recipient == recipient,
                RelayMessage.status == "pending",
            )
            .order_by(RelayMessage.created_at.asc(), RelayMessage.id.asc())
        )
    ).scalars().all()
    evict = pending_ids[: len(pending_ids) - max_per_recipient]
    if evict:
        await session.execute(
            update(RelayMessage)
            .where(RelayMessage.id.in_(evict))
            .values(status="dlq")
        )
        await session.flush()
    return "queued"


async def claim_for_recipient(
    session: AsyncSession,
    recipient: str,
    *,
    limit: int = CLAIM_LIMIT_DEFAULT,
    max_attempts: int = MAX_ATTEMPTS_DEFAULT,
) -> list[dict[str, Any]]:
    """Claim up to ``limit`` pending, unexpired rows (SKIP LOCKED).

    Each claim counts as a delivery attempt; rows at ``max_attempts``
    move to ``dlq`` instead of being returned. Returns plain dicts (no
    lazy session state escapes).
    """
    await session.execute(
        update(RelayMessage)
        .where(
            RelayMessage.recipient == recipient,
            RelayMessage.status == "pending",
            RelayMessage.attempts >= max_attempts,
        )
        .values(status="dlq")
    )
    rows = (
        await session.execute(
            select(RelayMessage)
            .where(
                RelayMessage.recipient == recipient,
                RelayMessage.status == "pending",
                RelayMessage.expires_at > func.now(),
            )
            .order_by(RelayMessage.created_at.asc(), RelayMessage.id.asc())
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
    ).scalars().all()
    claimed = []
    for row in rows:
        row.attempts += 1
        row.last_attempt_at = func.now()
        claimed.append(row)
    await session.flush()
    return [_row_to_dict(row) for row in claimed]


async def ack_delivered(session: AsyncSession, message_id: str) -> bool:
    """Settle a message on recipient ack. True when a pending row settled."""
    result = await session.execute(
        update(RelayMessage)
        .where(
            RelayMessage.message_id == message_id,
            RelayMessage.status == "pending",
        )
        .values(status="delivered", delivered_at=func.now())
    )
    await session.flush()
    return result.rowcount > 0


async def sweep_expired(session: AsyncSession) -> int:
    """Move pending rows past ``expires_at`` to ``expired``."""
    result = await session.execute(
        update(RelayMessage)
        .where(
            RelayMessage.status == "pending",
            RelayMessage.expires_at <= func.now(),
        )
        .values(status="expired")
    )
    await session.flush()
    return result.rowcount


async def queue_depth(
    session: AsyncSession, recipient: str | None = None
) -> int:
    stmt = select(func.count()).where(RelayMessage.status == "pending")
    if recipient is not None:
        stmt = stmt.where(RelayMessage.recipient == recipient)
    return (await session.execute(stmt)).scalar_one()


async def dlq_depth(session: AsyncSession, recipient: str | None = None) -> int:
    stmt = select(func.count()).where(RelayMessage.status == "dlq")
    if recipient is not None:
        stmt = stmt.where(RelayMessage.recipient == recipient)
    return (await session.execute(stmt)).scalar_one()


__all__ = [
    "CLAIM_LIMIT_DEFAULT",
    "MAX_ATTEMPTS_DEFAULT",
    "MAX_PER_RECIPIENT_DEFAULT",
    "ack_delivered",
    "claim_for_recipient",
    "dlq_depth",
    "enqueue",
    "queue_depth",
    "sweep_expired",
]
