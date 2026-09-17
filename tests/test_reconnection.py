"""Tests for agent reconnection, offline queue flushing, and duplicate connection handling."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from starlette.websockets import WebSocket, WebSocketState

from app.gateway.connection import ConnectionManager
from app.gateway.queue import OfflineQueue
from app.gateway.router import MessageRouter
from app.schemas.wire import RelayEnvelope
from app.storage.repository import GatewayRepository
from tests.conftest import TestAgentIdentity


@pytest.mark.asyncio
async def test_reconnection_flushes_offline_queue(
    agent_alice: TestAgentIdentity,
    agent_bob: TestAgentIdentity,
    connection_manager: ConnectionManager,
    offline_queue: OfflineQueue,
    message_router: MessageRouter,
    repository: GatewayRepository,
) -> None:
    """Messages buffered while agent is offline are automatically flushed on reconnect."""
    # 1. Alice sends two messages while Bob is offline
    env1 = agent_alice.make_envelope(recipient_id=agent_bob.agent_id)
    env2 = agent_alice.make_envelope(recipient_id=agent_bob.agent_id)

    res1 = await message_router.handle_relay_envelope(
        RelayEnvelope(relay_id="relay_reconnect_1", recipient=agent_bob.agent_id, envelope=env1),
        sender_agent_id=agent_alice.agent_id,
    )
    res2 = await message_router.handle_relay_envelope(
        RelayEnvelope(relay_id="relay_reconnect_2", recipient=agent_bob.agent_id, envelope=env2),
        sender_agent_id=agent_alice.agent_id,
    )

    assert res1["status"] == "queued"
    assert res2["status"] == "queued"

    # Verify queue count in DB
    assert await repository.count_queued(agent_bob.agent_id) == 2

    # 2. Bob connects
    mock_ws_bob = AsyncMock(spec=WebSocket)
    mock_ws_bob.client_state = WebSocketState.CONNECTED
    bob_frames: list[dict] = []
    mock_ws_bob.send_json.side_effect = lambda data: bob_frames.append(data)

    await connection_manager.register(
        agent_id=agent_bob.agent_id,
        public_key=agent_bob.public_key_b64,
        display_name="Bob",
        websocket=mock_ws_bob,
    )

    # 3. Queue flush
    flushed = await offline_queue.flush_to_agent(agent_bob.agent_id)
    assert flushed == 2

    # Bob received both frames in order
    assert len(bob_frames) == 2
    assert bob_frames[0]["type"] == "delivery"
    assert bob_frames[0]["relay_id"] == "relay_reconnect_1"
    assert bob_frames[1]["relay_id"] == "relay_reconnect_2"

    # Messages are SENT but not yet delivered: delivery is confirmed by the
    # recipient's ack, not by the gateway writing to the socket.
    assert await repository.count_queued(agent_bob.agent_id) == 2

    # An immediate second flush sends nothing - the rows are leased to this
    # replica, which is what stops a second replica double-sending them.
    assert await offline_queue.flush_to_agent(agent_bob.agent_id) == 0

    # Bob acks both frames; only now are they delivered.
    await offline_queue.acknowledge("relay_reconnect_1")
    await offline_queue.acknowledge("relay_reconnect_2")
    assert await repository.count_queued(agent_bob.agent_id) == 0


@pytest.mark.asyncio
async def test_duplicate_connection_displaces_old(
    agent_alice: TestAgentIdentity,
    connection_manager: ConnectionManager,
) -> None:
    """When an agent reconnects from a new socket, the old socket is closed and displaced."""
    ws_old = AsyncMock(spec=WebSocket)
    ws_old.client_state = WebSocketState.CONNECTED

    ws_new = AsyncMock(spec=WebSocket)
    ws_new.client_state = WebSocketState.CONNECTED

    # Register first
    await connection_manager.register(
        agent_id=agent_alice.agent_id,
        public_key=agent_alice.public_key_b64,
        display_name="Alice 1",
        websocket=ws_old,
    )
    assert connection_manager.active_count == 1
    assert connection_manager.get(agent_alice.agent_id).websocket == ws_old

    # Register second from new socket
    await connection_manager.register(
        agent_id=agent_alice.agent_id,
        public_key=agent_alice.public_key_b64,
        display_name="Alice 2",
        websocket=ws_new,
    )
    # Total count remains 1
    assert connection_manager.active_count == 1
    assert connection_manager.get(agent_alice.agent_id).websocket == ws_new
    # Old socket was closed
    ws_old.close.assert_awaited_once()
