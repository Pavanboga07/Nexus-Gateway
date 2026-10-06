"""Relay database wiring: async SQLAlchemy + asyncpg, Postgres only.

Fresh empty database is assumed. Boot calls init_schema() (create_all)
then verify_schema() which crashes loudly naming any missing table.
"""

from __future__ import annotations

import logging
import os
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from relay.models import TABLE_NAMES, Base

logger = logging.getLogger("relay.db")


def normalize_database_url(url: str) -> str:
    """Normalize a Postgres URL for asyncpg, parsed properly.

    - ``postgresql://`` -> ``postgresql+asyncpg://``
    - ``sslmode=require`` query param -> ``ssl=require`` (asyncpg dialect)
    - ``channel_binding`` query param is dropped (asyncpg rejects it)
    - every other param is preserved verbatim and in order

    Parsing with ``urllib.parse`` instead of string replacement means a
    password that happens to contain ``sslmode=require`` is left alone.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("postgresql", "postgresql+asyncpg"):
        return url  # not ours to normalize; pass through untouched
    scheme = "postgresql+asyncpg" if parsed.scheme == "postgresql" else parsed.scheme
    params: list[tuple[str, str]] = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if key == "channel_binding":
            continue
        if key == "sslmode" and value == "require":
            params.append(("ssl", "require"))
        else:
            params.append((key, value))
    return urlunparse(parsed._replace(scheme=scheme, query=urlencode(params)))


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
    "verify_schema",
]
