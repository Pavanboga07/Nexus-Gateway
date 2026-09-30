"""Relay database wiring (async SQLAlchemy + asyncpg, Postgres only).

Deployment uses hosted Neon via ``RELAY_DATABASE_URL`` (operator step in
Task V8 — not this task). Tests use local ``nexus_postgres`` :5433 with
a separate ``nexus_relay_test`` database (see tests/relay_db.py).
"""

from __future__ import annotations

import logging
import os

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from relay.models import TABLE_NAMES, Base


logger = logging.getLogger("relay.db")


def normalize_database_url(url: str) -> str:
    """Accept plain ``postgresql://`` URLs (what every dashboard hands out)
    and adapt them to what this service needs: the asyncpg driver plus the
    ``ssl`` query spelling asyncpg understands. Anything else passes through
    untouched so explicit asyncpg URLs never change meaning."""
    if url.startswith("postgresql://"):
        url = "postgresql+asyncpg://" + url[len("postgresql://"):]
    # asyncpg wants ssl=require; dashboards emit sslmode=require.
    url = url.replace("sslmode=require", "ssl=require")
    # Neon appends channel_binding=require (a libpq-ism for SCRAM binding).
    # asyncpg does not accept that keyword, so strip it: SCRAM still
    # authenticates, just without channel binding — identical to local runs.
    parts = url.split("?", 1)
    if len(parts) == 2:
        kept = "&".join(
            p for p in parts[1].split("&") if not p.startswith("channel_binding=")
        )
        url = parts[0] + ("?" + kept if kept else "")
    return url


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
    return normalize_database_url(url)


def make_engine(url: str) -> AsyncEngine:
    # prepared_statement_cache_size=0: Neon (and any PgBouncer-style
    # pooler) runs in transaction mode, where server-side prepared
    # statements fail. Disabling the cache keeps every query working
    # through a pooler; direct connections are unaffected.
    return create_async_engine(
        url,
        pool_size=5,
        max_overflow=5,
        connect_args={"prepared_statement_cache_size": 0},
    )


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
    except Exception as exc:
        # Never silent: a health check that swallows its reason turns every
        # future outage into a guessing game (learned the hard way).
        logger.warning("readiness check failed: %s", type(exc).__name__)
        return False


__all__ = [
    "check_ready",
    "init_schema",
    "make_engine",
    "make_session_factory",
    "resolve_database_url",
    "truncate_all",
]
