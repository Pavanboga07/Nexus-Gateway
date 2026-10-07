"""Agent presence heartbeats. One row per agent; rows survive disconnect."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from relay.models import Presence

PRESENCE_STALE_SECONDS_DEFAULT = 120.0


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


async def heartbeat(session: AsyncSession, agent_id: str, *, replica_id: str = "", display_name: str | None = None) -> None:
    values: dict[str, Any] = {"agent_id": agent_id, "replica_id": replica_id, "last_heartbeat": func.now()}
    if display_name is not None:
        values["display_name"] = display_name
    stmt = pg_insert(Presence).values(**values)
    stmt = stmt.on_conflict_do_update(
        index_elements=["agent_id"],
        set_={
            "replica_id": stmt.excluded.replica_id,
            "last_heartbeat": func.now(),
            **({"display_name": stmt.excluded.display_name} if display_name is not None else {}),
        },
    )
    await session.execute(stmt)
    await session.flush()


async def get_presence(
    session: AsyncSession, agent_id: str, *, stale_after_seconds: float = PRESENCE_STALE_SECONDS_DEFAULT
) -> dict[str, Any] | None:
    row = (await session.execute(select(Presence).where(Presence.agent_id == agent_id))).scalar_one_or_none()
    if row is None:
        return None
    last = row.last_heartbeat
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    stale = (datetime.now(timezone.utc) - last).total_seconds() > stale_after_seconds
    return _row_to_dict(row, stale=stale)


__all__ = ["PRESENCE_STALE_SECONDS_DEFAULT", "get_presence", "heartbeat"]
