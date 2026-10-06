"""Relay presence tests (PG-gated).

Heartbeat writes to the agent_presence table; rows survive disconnect
(reconnect visibility).
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
