"""Test helpers for V2 relay suites (NOT a test module).

Database decision (documented here per the task): the relay targets
Postgres ONLY (SQLAlchemy async + asyncpg) because queue claims need
``SELECT ... FOR UPDATE SKIP LOCKED`` for safe concurrent delivery.
There is no SQLite backend. Tests reuse the local ``nexus_postgres``
server read-only (a SEPARATE ``nexus_relay_test`` database is created;
``nexus``/``nexus_test``/``neondb`` data is never touched) and skip
gracefully when the server is unavailable.

All ``relay.*`` imports are lazy so collection never breaks before the
implementation lands (TDD red phase).
"""

from __future__ import annotations

import asyncio

import pytest

ADMIN_URL = "postgresql+asyncpg://nexus:nexus@localhost:5433/nexus"
TEST_URL = "postgresql+asyncpg://nexus:nexus@localhost:5433/nexus_relay_test"
TEST_DB_NAME = "nexus_relay_test"

SKIP_REASON = "local relay Postgres (nexus_postgres :5433) is not available"


def pg_available(timeout: float = 3.0) -> bool:
    """True when the local Postgres server answers on :5433."""

    async def _probe() -> bool:
        import asyncpg

        try:
            conn = await asyncio.wait_for(
                asyncpg.connect(
                    host="localhost",
                    port=5433,
                    user="nexus",
                    password="nexus",
                    database="nexus",
                ),
                timeout=timeout,
            )
            await conn.close()
            return True
        except Exception:
            return False

    return asyncio.run(_probe())


# --- per-test event loop -------------------------------------------------
#
# asyncpg pools bind to the loop that first connects. The fixture engine
# is built during setup while test bodies run coroutines later, so both
# must share ONE loop per test (asyncio.run per call breaks the pool
# with "Event loop is closed"). The conftest fixture enters the loop;
# run() reuses it.

_loop_state: dict = {"loop": None}


def _enter_test_loop():
    """Create this test's loop (conftest calls this before setup)."""
    loop = asyncio.new_event_loop()
    _loop_state["loop"] = loop
    return loop


def _exit_test_loop() -> None:
    """Close this test's loop (conftest calls this after teardown)."""
    loop = _loop_state["loop"]
    _loop_state["loop"] = None
    if loop is not None and not loop.is_closed():
        loop.close()


def run(coro):
    """Run one coroutine on this test's loop (sync tests, no plugin)."""
    loop = _loop_state["loop"]
    if loop is None or loop.is_closed():
        return asyncio.run(coro)
    return loop.run_until_complete(coro)


def fresh_relay_engine():
    """Create a FRESH test database + engine (skip when PG is down).

    Guarded to the ``nexus_relay_test`` name so a typo can never drop a
    real database.
    """
    if not pg_available():
        pytest.skip(SKIP_REASON)
    assert TEST_DB_NAME == "nexus_relay_test"

    async def _build():
        import asyncpg

        from relay.db import make_engine

        admin = await asyncpg.connect(
            host="localhost", port=5433, user="nexus",
            password="nexus", database="nexus",
        )
        try:
            await admin.execute(
                f"DROP DATABASE IF EXISTS {TEST_DB_NAME} WITH (FORCE)"
            )
            await admin.execute(f"CREATE DATABASE {TEST_DB_NAME}")
        finally:
            await admin.close()
        engine = make_engine(TEST_URL)
        from relay.db import init_schema

        await init_schema(engine)
        return engine

    try:
        return run(_build())
    except Exception as exc:
        pytest.skip(f"{SKIP_REASON} ({type(exc).__name__})")


async def dispose_relay_engine(engine) -> None:
    await engine.dispose()


# --- identity / envelope / card builders ------------------------------------


def new_agent():
    """Fresh Ed25519 agent: (private_key, public_b64, agent_id)."""
    import base64

    from app.identity import crypto

    priv, pub = crypto.generate_keypair()
    raw = crypto.public_key_bytes(pub)
    return priv, base64.b64encode(raw).decode("ascii"), crypto.agent_id_from_public_key(raw)


_FIXED_TS = "2026-09-20T12:00:00Z"
_FIXED_EXP = "2026-09-20T12:05:00Z"


def make_envelope(
    *,
    sender: str,
    recipient: str,
    message_type: str = "request",
    message_id: str = "msg_test001",
    correlation_id: str = "corr_test001",
    payload: dict | None = None,
    timestamp: str = _FIXED_TS,
    expires_at: str = _FIXED_EXP,
) -> dict:
    from relay.envelope import PROTOCOL, VERSION

    return {
        "protocol": PROTOCOL,
        "version": VERSION,
        "message_id": message_id,
        "correlation_id": correlation_id,
        "sender": sender,
        "recipient": recipient,
        "timestamp": timestamp,
        "expires_at": expires_at,
        "message_type": message_type,
        "payload": dict(payload) if payload is not None else {"action": "ping"},
    }


def sign_envelope(priv, unsigned: dict) -> dict:
    from relay.envelope import sign_envelope as _sign

    return _sign(priv, unsigned)


def make_card(
    *,
    agent_id: str,
    public_key: str,
    handle: str | None = None,
    display_name: str = "Test Agent",
    endpoint: str = "ws://test.invalid/ws",
) -> dict:
    card = {
        "type": "agent-card",
        "protocol": "nexus-a2a",
        "version": "0.3",
        "agent_id": agent_id,
        "display_name": display_name,
        "public_key": public_key,
        "endpoint": endpoint,
        "capabilities": [],
        "supported_purposes": [],
        "issued_at": _FIXED_TS,
        "expires_at": "2027-09-20T12:00:00Z",
    }
    if handle is not None:
        card["handle"] = handle
    return card


def sign_card_dict(priv, card: dict) -> dict:
    from relay.directory import sign_card

    return sign_card(priv, card)
