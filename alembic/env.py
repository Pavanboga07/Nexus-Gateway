"""Alembic environment (async engine, models as source of truth)."""

from __future__ import annotations

import asyncio
import os

from alembic import context
from sqlalchemy.ext.asyncio import create_async_engine

from relay.models import Base

config = context.config


def get_url() -> str:
    url = os.environ.get("RELAY_DATABASE_URL", "")
    if not url:
        raise RuntimeError(
            "Set RELAY_DATABASE_URL to run relay migrations."
        )
    return url


def run_migrations_offline() -> None:
    context.configure(
        url=get_url(),
        target_metadata=Base.metadata,
        literal_binds=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_async_engine(get_url())

    async def main() -> None:
        async with engine.connect() as connection:
            await connection.run_sync(
                lambda conn: context.configure(
                    connection=conn, target_metadata=Base.metadata
                )
            )
            async with context.begin_transaction():
                await connection.run_sync(
                    lambda conn: context.run_migrations()
                )
        await engine.dispose()

    asyncio.run(main())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
