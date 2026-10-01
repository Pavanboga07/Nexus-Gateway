"""Relay verified-boot tests (TDD add).

BOOT THAT CANNOT LIE: lifespan runs create_all then verifies every
expected table exists, crashing loudly naming any missing table.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text

from tests.relay_db import run


def test_boot_tables_present_after_init(relay_engine):
    from relay.db import verify_schema
    from relay.models import TABLE_NAMES

    async def main():
        await verify_schema(relay_engine)
        async with relay_engine.connect() as conn:
            rows = (await conn.execute(text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'"))).scalars().all()
        return set(rows)

    present = run(main())
    for name in TABLE_NAMES:
        assert name in present


def test_sabotaged_schema_fails_verifier_loudly(relay_engine):
    from relay.db import verify_schema

    async def main():
        async with relay_engine.begin() as conn:
            await conn.execute(text('DROP TABLE "relay_messages"'))
        try:
            await verify_schema(relay_engine)
            return "no-error"
        except RuntimeError as exc:
            return str(exc)

    message = run(main())
    assert message != "no-error"
    assert "relay_messages" in message
    assert "RELAY BOOT FAILED" in message or "missing tables" in message.lower()
