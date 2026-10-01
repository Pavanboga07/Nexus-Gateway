"""Relay database wiring: async SQLAlchemy + asyncpg, Postgres only.

Fresh empty database is assumed. Boot calls init_schema() (create_all)
then verify_schema() which crashes loudly naming any missing table.
"""

from __future__ import annotations

import logging
import os

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from relay.models import TABLE_NAMES, Base

logger = logging.getLogger("relay.db")


def normalize_database_url(url: str) -> str:
    if url.startswith("postgresql://"):
        url = "postgresql+asyncpg://" + url[len("postgresql://"):]
    url = url.replace("sslmode=require", "ssl=require")
    parts = url.split("?", 1)
    if len(parts) == 2:
        kept = "&".join(p for p in parts[1].split("&") if not p.startswith("channel_binding="))
        url = parts[0] + ("?" + kept if kept else "")
    return url


def resolve_database_url(explicit: str | None = None) -> str:
    url = explicit or os.environ.get("RELAY_DATABASE_URL")
    if not url:
        raise RuntimeError(
            "No relay database configured: pass database_url or set "
            "RELAY_DATABASE_URL."
        )
    return normalize_database_url(url.strip())


def make_engine(url: str) -> AsyncEngine:
    return create_async_engine(
        url,
        pool_size=5,
        max_overflow=5,
        connect_args={"prepared_statement_cache_size": 0},
    )


def make_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)


async def init_schema(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def verify_schema(engine: AsyncEngine) -> None:
    async with engine.connect() as conn:
        rows = (await conn.execute(text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'"))).scalars().all()
    present = set(rows)
    missing = [name for name in TABLE_NAMES if name not in present]
    if missing:
        raise RuntimeError(f"RELAY BOOT FAILED: missing tables: {', '.join(missing)}")


async def init_and_verify(engine: AsyncEngine) -> None:
    await init_schema(engine)
    await verify_schema(engine)


async def truncate_all(engine: AsyncEngine) -> None:
    tables = ", ".join(f'"{name}"' for name in TABLE_NAMES)
    async with engine.begin() as conn:
        await conn.execute(text(f"TRUNCATE {tables}"))


async def check_ready(engine: AsyncEngine) -> bool:
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception:
        logger.exception("readiness check failed")
        return False


__all__ = [
    "check_ready",
    "init_and_verify",
    "init_schema",
    "make_engine",
    "make_session_factory",
    "resolve_database_url",
    "normalize_database_url",
    "truncate_all",
    "verify_schema",
]
