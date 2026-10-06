"""Periodic retention cleanup.

Runs on a lifespan background task (see ``relay.main``): expires
pending queue rows, purges delivered/expired messages past the
retention window, removes used/expired invites, and drops stale
rate-limit / claim-attempt rows. Without this the tables grow forever —
the old code shipped ``queue.sweep_expired()`` but nothing ever called
it.

Every function returns the number of rows removed so the counts can be
surfaced in ``/metrics``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from relay import directory, invites, queue
from relay.models import RelayMessage

RATE_HIT_RETENTION_SECONDS = 86400  # 24h
CLAIM_ATTEMPT_RETENTION_SECONDS = 86400  # 24h


async def run_cleanup(session: AsyncSession, *, delivered_retention_days: int = 7) -> dict[str, int]:
    """Run one full retention pass. Callers commit the session."""
    swept = await queue.sweep_expired(session)

    cutoff = datetime.now(timezone.utc) - timedelta(days=delivered_retention_days)
    delivered = (
        await session.execute(
            delete(RelayMessage).where(
                RelayMessage.status == "delivered",
                RelayMessage.delivered_at < cutoff,
            )
        )
    ).rowcount or 0
    expired = (
        await session.execute(
            delete(RelayMessage).where(
                RelayMessage.status == "expired",
                RelayMessage.created_at < cutoff,
            )
        )
    ).rowcount or 0

    invites_purged = await invites.purge_expired_invites(session)
    attempts_purged = await invites.purge_old_claim_attempts(
        session, older_than_seconds=CLAIM_ATTEMPT_RETENTION_SECONDS
    )
    rate_hits_purged = await directory.purge_old_rate_hits(
        session, older_than_seconds=RATE_HIT_RETENTION_SECONDS
    )
    await session.flush()
    return {
        "swept_expired": swept,
        "purged_delivered": delivered,
        "purged_expired": expired,
        "purged_invites": invites_purged,
        "purged_claim_attempts": attempts_purged,
        "purged_rate_hits": rate_hits_purged,
    }


__all__ = [
    "CLAIM_ATTEMPT_RETENTION_SECONDS",
    "RATE_HIT_RETENTION_SECONDS",
    "run_cleanup",
]
