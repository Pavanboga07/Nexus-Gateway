"""V2 relay presence tests (TDD red first, PG-gated).

Heartbeat writes to the agent_presence table; rows survive disconnect
(reconnect visibility); listing exposes staleness.
"""

from __future__ import annotations

from tests.relay_db import new_agent, run


def test_heartbeat_creates_and_updates_presence(relay_engine):
    from relay import presence
    from relay.db import make_session_factory

    _, _, agent_id = new_agent()
    Session = make_session_factory(relay_engine)

    async def main():
        async with Session() as s:
            await presence.heartbeat(s, agent_id, replica_id="relay-1")
            await s.commit()
        async with Session() as s:
            first = await presence.get_presence(s, agent_id)
        async with Session() as s:
            await presence.heartbeat(
                s, agent_id, replica_id="relay-1", display_name="Bo"
            )
            await s.commit()
        async with Session() as s:
            second = await presence.get_presence(s, agent_id)
            return first, second

    first, second = run(main())
    assert first is not None
    assert first["agent_id"] == agent_id
    assert first["replica_id"] == "relay-1"
    assert second["display_name"] == "Bo"
    assert second["last_heartbeat"] >= first["last_heartbeat"]


def test_unknown_agent_presence_is_none(relay_engine):
    from relay import presence
    from relay.db import make_session_factory

    _, _, agent_id = new_agent()
    Session = make_session_factory(relay_engine)

    async def main():
        async with Session() as s:
            return await presence.get_presence(s, agent_id)

    assert run(main()) is None


def test_presence_list_marks_stale_rows(relay_engine):
    from relay import presence
    from relay.db import make_session_factory

    _, _, fresh_id = new_agent()
    _, _, stale_id = new_agent()
    Session = make_session_factory(relay_engine)

    async def main():
        async with Session() as s:
            await presence.heartbeat(s, fresh_id, replica_id="relay-1")
            await presence.heartbeat(s, stale_id, replica_id="relay-1")
            await s.commit()
            # Age one row far beyond the stale threshold.
            from sqlalchemy import text

            await s.execute(
                text(
                    "UPDATE agent_presence SET last_heartbeat = "
                    "NOW() - INTERVAL '1 hour' WHERE agent_id = :aid"
                ),
                {"aid": stale_id},
            )
            await s.commit()
        async with Session() as s:
            return await presence.list_presence(s, stale_after_seconds=90)

    rows = run(main())
    by_id = {r["agent_id"]: r for r in rows}
    assert by_id[fresh_id]["stale"] is False
    assert by_id[stale_id]["stale"] is True
