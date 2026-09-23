"""Agent presence heartbeats (Postgres backed).

One row per agent (``agent_presence``): the relay process that last saw
the agent (``replica_id``) plus ``last_heartbeat``. Rows survive socket
disconnects, so a reconnecting agent stays visible; readers decide
staleness from ``last_heartbeat``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from relay.models import Presence


def _row_to_dict(row: Presence, *, stale: bool = False) -> dict[str, Any]:
    last = row.last_heartbeat
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    return {
        "agent_id": row.agent_id,
        "replica_id": row.replica_id,
        "display_name": row.display_name,
        "last_heartbeat": last,
        "stale": stale,
    }


async def heartbeat(
    session: AsyncSession,
    agent_id: str,
    *,
    replica_id: str = "",
    display_name: str | None = None,
) -> None:
    """Upsert the agent's presence row (single statement, replica-safe)."""
    values: dict[str, Any] = {
        "agent_id": agent_id,
        "replica_id": replica_id,
        "last_heartbeat": func.now(),
    }
    if display_name is not None:
        values["display_name"] = display_name
    stmt = pg_insert(Presence).values(**values)
    stmt = stmt.on_conflict_do_update(
        index_elements=["agent_id"],
        set_={
            "replica_id": stmt.excluded.replica_id,
            "last_heartbeat": func.now(),
            **(
                {"display_name": stmt.excluded.display_name}
                if display_name is not None
                else {}
            ),
        },
    )
    await session.execute(stmt)
    await session.flush()


async def get_presence(
    session: AsyncSession, agent_id: str
) -> dict[str, Any] | None:
    """Presence dict for one agent; None when never seen."""
    row = (
        await session.execute(
            select(Presence).where(Presence.agent_id == agent_id)
        )
    ).scalar_one_or_none()
    if row is None:
        return None
    return _row_to_dict(row)


async def list_presence(
    session: AsyncSession, *, stale_after_seconds: float = 90.0
) -> list[dict[str, Any]]:
    """Every known agent; ``stale`` when the heartbeat is too old."""
    rows = (
        await session.execute(select(Presence).order_by(Presence.agent_id))
    ).scalars().all()
    now = datetime.now(timezone.utc)
    out = []
    for row in rows:
        last = row.last_heartbeat
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        out.append(
            _row_to_dict(
                row,
                stale=(now - last).total_seconds() > stale_after_seconds,
            )
        )
    return out


__all__ = ["get_presence", "heartbeat", "list_presence"]
