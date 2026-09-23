"""Relay database wiring (async SQLAlchemy + asyncpg, Postgres only).

Deployment uses hosted Neon via ``RELAY_DATABASE_URL`` (operator step in
Task V8 — not this task). Tests use local ``nexus_postgres`` :5433 with
a separate ``nexus_relay_test`` database (see tests/relay_db.py).
"""

from __future__ import annotations

import os

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from relay.models import TABLE_NAMES, Base


def resolve_database_url(explicit: str | None = None) -> str:
    """Explicit URL wins, else ``RELAY_DATABASE_URL`` env. Never defaults
    to a guess: connecting to the wrong Postgres silently is worse than
    failing loudly."""
    url = explicit or os.environ.get("RELAY_DATABASE_URL")
    if not url:
        raise RuntimeError(
            "No relay database configured: pass database_url or set "
            "RELAY_DATABASE_URL."
        )
    return url


def make_engine(url: str) -> AsyncEngine:
    return create_async_engine(url, pool_size=5, max_overflow=5)


def make_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(
        bind=engine, class_=AsyncSession, expire_on_commit=False
    )


async def init_schema(engine: AsyncEngine) -> None:
    """Create missing tables (idempotent; safe for single-process v1).

    Operator-managed migrations live in alembic/; this keeps fresh
    deploys and tests bootable from the models as source of truth.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def truncate_all(engine: AsyncEngine) -> None:
    """Empty every relay table (tests only)."""
    tables = ", ".join(f'"{name}"' for name in TABLE_NAMES)
    async with engine.begin() as conn:
        await conn.execute(text(f"TRUNCATE {tables}"))


async def check_ready(engine: AsyncEngine) -> bool:
    """True when a trivial query succeeds (drives /readyz)."""
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


__all__ = [
    "check_ready",
    "init_schema",
    "make_engine",
    "make_session_factory",
    "resolve_database_url",
    "truncate_all",
]
