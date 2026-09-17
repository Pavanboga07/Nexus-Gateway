"""Schema lifecycle for the Nexus Gateway.

Single source of truth for how the gateway's database schema is created.

Previously the gateway called ``Base.metadata.create_all()`` at every startup
*and* shipped an Alembic migration, so migrations were effectively decorative
and could never express an alteration (for example the partial unique index
that handle arbitration now depends on). This module replaces that with an
explicit, configurable policy:

    auto     create tables directly when missing (dev convenience), then
             verify - never silently diverges from the models
    migrate  run Alembic migrations to head (staging/production)
    verify   assert the schema is present; never modify it

``migrate`` is the recommended production setting; ``auto`` exists so a
developer can start the gateway against an empty database without running
Alembic by hand.
"""

from __future__ import annotations

import logging
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import AsyncEngine

from app.storage.models import Base

logger = logging.getLogger(__name__)

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"
ALEMBIC_INI = Path(__file__).resolve().parent.parent / "alembic.ini"

REQUIRED_TABLES = frozenset(Base.metadata.tables)


class SchemaError(RuntimeError):
    """Raised when the database schema is missing or cannot be prepared."""


def _alembic_config(database_url: str) -> Config:
    """Build an Alembic Config pointed at the gateway's migrations."""
    if ALEMBIC_INI.exists():
        cfg = Config(str(ALEMBIC_INI))
    else:  # pragma: no cover - packaging without the ini
        cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    cfg.set_main_option("sqlalchemy.url", database_url)
    return cfg


def _sync_url(database_url: str) -> str:
    """Alembic's sync runner cannot use asyncpg."""
    return database_url.replace("+asyncpg", "+psycopg2")


async def _existing_tables(engine: AsyncEngine) -> set[str]:
    async with engine.connect() as conn:
        return set(await conn.run_sync(lambda c: inspect(c).get_table_names()))


async def ensure_schema(
    engine: AsyncEngine,
    *,
    mode: str,
    database_url: str,
) -> None:
    """Prepare the schema according to ``mode``. Raises SchemaError on failure."""
    normalized = (mode or "auto").strip().lower()
    if normalized not in {"auto", "migrate", "verify"}:
        raise SchemaError(
            f"Unknown schema mode {mode!r}; expected auto, migrate, or verify."
        )

    present = await _existing_tables(engine)

    if normalized == "auto":
        if not present:
            logger.info("schema_mode=auto: creating tables from models (empty DB)")
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
        present = await _existing_tables(engine)
    elif normalized == "migrate":
        logger.info("schema_mode=migrate: running alembic upgrade head")
        try:
            cfg = _alembic_config(_sync_url(database_url))
            command.upgrade(cfg, "head")
        except Exception as exc:  # pragma: no cover - depends on live DB
            raise SchemaError(f"Alembic migration failed: {exc}") from exc
        present = await _existing_tables(engine)

    missing = REQUIRED_TABLES - present
    if missing:
        raise SchemaError(
            "Database schema is incomplete; missing tables: "
            f"{', '.join(sorted(missing))}. Run migrations "
            "(GATEWAY_SCHEMA_MODE=migrate) or start with "
            "GATEWAY_SCHEMA_MODE=auto on an empty database."
        )

    logger.info(
        "Schema ready (mode=%s, tables=%d)", normalized, len(present)
    )


__all__ = ["SchemaError", "ensure_schema", "REQUIRED_TABLES"]
