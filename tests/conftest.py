"""Shared fixtures for the NEW repo test suite (V2 relay and beyond).

Additive only: existing V0/V1 tests are unaffected. Relay tests run
against a SEPARATE local database (``nexus_relay_test``) on the reused
``nexus_postgres`` server (:5433) and skip gracefully when it is down,
mirroring the old repo's conftest skip idiom. Never touches
nexus/nexus_test/neondb data.
"""

from __future__ import annotations

import pytest

# Relay imports are lazy (inside fixtures/helpers in tests/relay_db.py) so
# this conftest never breaks collection when relay modules do not exist yet.


@pytest.fixture(scope="function")
def relay_engine():
    """Fresh ``nexus_relay_test`` database + async engine per test.

    Skips when the local Postgres container is unavailable. The database
    is dropped and recreated for isolation (never touches other DBs).
    Setup, test body, and teardown share one event loop: asyncpg pools
    bind to the connecting loop, so a fresh loop per coroutine would
    break every checkout.
    """
    from tests import relay_db
    from tests.relay_db import fresh_relay_engine

    relay_db._enter_test_loop()
    try:
        engine = fresh_relay_engine()
    except BaseException:
        relay_db._exit_test_loop()
        raise
    yield engine
    try:
        relay_db.run(relay_db.dispose_relay_engine(engine))
    finally:
        relay_db._exit_test_loop()
