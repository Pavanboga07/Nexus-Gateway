"""Durable outbox queue: pending until acked, TTL expiry, DLQ, UNIQUE dedup."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from relay.envelope import parse_iso
from relay.models import RelayMessage

logger = logging.getLogger("relay")

MAX_ATTEMPTS_DEFAULT = 5
MAX_PER_RECIPIENT_DEFAULT = 1000
CLAIM_LIMIT_DEFAULT = 50
DLQ_LIST_LIMIT_DEFAULT = 50
DLQ_LIST_LIMIT_MAX = 100


def _row_to_dict(row: RelayMessage) -> dict[str, Any]:
    return {
        "message_id": row.message_id,
        "sender": row.sender,
        "recipient": row.recipient,
        "envelope": dict(row.envelope),
        "attempts": row.attempts,
        "status": row.status,
        "expires_at": row.expires_at,
    }


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


async def enqueue(session: AsyncSession, *, envelope: dict[str, Any], max_per_recipient: int = MAX_PER_RECIPIENT_DEFAULT) -> str:
    try:
        message_id = envelope["message_id"]
        sender = envelope["sender"]
        recipient = envelope["recipient"]
        expires_at = _as_utc(parse_iso(envelope["expires_at"]))
    except KeyError as exc:
        raise ValueError(f"envelope is missing {exc}") from exc
    stmt = (
        pg_insert(RelayMessage)
        .values(message_id=message_id, sender=sender, recipient=recipient, envelope=dict(envelope), status="pending", expires_at=expires_at)
        .on_conflict_do_nothing(index_elements=["message_id"])
        .returning(RelayMessage.id)
    )
    inserted = (await session.execute(stmt)).scalar_one_or_none()
    await session.flush()
    if inserted is None:
        return "dedup_hit"
    # Bound the per-recipient backlog without loading every pending id into
    # Python: count first, then evict the oldest `excess` rows in one
    # statement. The just-inserted row is the newest, so it is never evicted.
    pending_count = (
        await session.execute(
            select(func.count())
            .select_from(RelayMessage)
            .where(RelayMessage.recipient == recipient, RelayMessage.status == "pending")
        )
    ).scalar_one()
    excess = pending_count - max_per_recipient
    if excess > 0:
        oldest = (
            await session.execute(
                select(RelayMessage.id, RelayMessage.message_id)
                .where(RelayMessage.recipient == recipient, RelayMessage.status == "pending")
                .order_by(RelayMessage.created_at.asc(), RelayMessage.id.asc())
                .limit(excess)
            )
        ).all()
        oldest_ids = [row_id for row_id, _ in oldest]
        evicted_mids = [mid for _, mid in oldest]
        await session.execute(
            update(RelayMessage).where(RelayMessage.id.in_(oldest_ids)).values(status="dlq")
        )
        await session.flush()
        # Capacity evictions are silent drops from the recipient's point of
        # view — log them loudly with the message IDs so operators can see
        # what was shed.
        logger.warning(
            "queue capacity eviction: recipient=%s evicted=%d message_ids=%s",
            recipient,
            len(evicted_mids),
            ",".join(evicted_mids),
        )
    return "queued"


async def claim_for_recipient(session: AsyncSession, recipient: str, *, limit: int = CLAIM_LIMIT_DEFAULT, max_attempts: int = MAX_ATTEMPTS_DEFAULT) -> list[dict[str, Any]]:
    await session.execute(update(RelayMessage).where(RelayMessage.recipient == recipient, RelayMessage.status == "pending", RelayMessage.attempts >= max_attempts).values(status="dlq"))
    rows = (await session.execute(select(RelayMessage).where(RelayMessage.recipient == recipient, RelayMessage.status == "pending", RelayMessage.expires_at > func.now()).order_by(RelayMessage.created_at.asc(), RelayMessage.id.asc()).limit(limit).with_for_update(skip_locked=True))).scalars().all()
    claimed = []
    for row in rows:
        row.attempts += 1
        row.last_attempt_at = func.now()
        claimed.append(row)
    await session.flush()
    return [_row_to_dict(row) for row in claimed]


async def ack_delivered(session: AsyncSession, message_id: str) -> bool:
    result = await session.execute(update(RelayMessage).where(RelayMessage.message_id == message_id, RelayMessage.status == "pending").values(status="delivered", delivered_at=func.now()))
    await session.flush()
    return result.rowcount > 0


async def sweep_expired(session: AsyncSession) -> int:
    result = await session.execute(update(RelayMessage).where(RelayMessage.status == "pending", RelayMessage.expires_at <= func.now()).values(status="expired"))
    await session.flush()
    return result.rowcount


async def queue_depth(session: AsyncSession, recipient: str | None = None) -> int:
    stmt = select(func.count()).where(RelayMessage.status == "pending")
    if recipient is not None:
        stmt = stmt.where(RelayMessage.recipient == recipient)
    return (await session.execute(stmt)).scalar_one()


async def dlq_depth(session: AsyncSession, recipient: str | None = None) -> int:
    stmt = select(func.count()).where(RelayMessage.status == "dlq")
    if recipient is not None:
        stmt = stmt.where(RelayMessage.recipient == recipient)
    return (await session.execute(stmt)).scalar_one()


async def list_dlq(
    session: AsyncSession,
    *,
    recipient: str | None = None,
    limit: int = DLQ_LIST_LIMIT_DEFAULT,
    offset: int = 0,
) -> tuple[int, list[dict[str, Any]]]:
    """Paginated DLQ inspection. Returns (total, items) newest-first."""
    limit = max(1, min(limit, DLQ_LIST_LIMIT_MAX))
    offset = max(0, offset)
    base = select(RelayMessage).where(RelayMessage.status == "dlq")
    if recipient is not None:
        base = base.where(RelayMessage.recipient == recipient)
    total = (await session.execute(select(func.count()).select_from(base.subquery()))).scalar_one()
    rows = (
        await session.execute(
            base.order_by(RelayMessage.created_at.desc(), RelayMessage.id.desc()).limit(limit).offset(offset)
        )
    ).scalars().all()
    return total, [_row_to_dict(row) for row in rows]


async def redrive_dlq(
    session: AsyncSession,
    *,
    recipient: str | None = None,
    message_ids: list[str] | None = None,
) -> int:
    """Move DLQ rows back to pending for redelivery. Returns rows moved.

    Attempts reset to 0 so a redriven message is not immediately
    re-DLQed by the claim path's max-attempts rule.
    """
    stmt = update(RelayMessage).where(RelayMessage.status == "dlq")
    if recipient is not None:
        stmt = stmt.where(RelayMessage.recipient == recipient)
    if message_ids:
        stmt = stmt.where(RelayMessage.message_id.in_(message_ids))
    result = await session.execute(stmt.values(status="pending", attempts=0))
    await session.flush()
    return result.rowcount or 0


__all__ = [
    "CLAIM_LIMIT_DEFAULT",
    "DLQ_LIST_LIMIT_DEFAULT",
    "DLQ_LIST_LIMIT_MAX",
    "MAX_ATTEMPTS_DEFAULT",
    "MAX_PER_RECIPIENT_DEFAULT",
    "ack_delivered",
    "claim_for_recipient",
    "dlq_depth",
    "enqueue",
    "list_dlq",
    "queue_depth",
    "redrive_dlq",
    "sweep_expired",
]
