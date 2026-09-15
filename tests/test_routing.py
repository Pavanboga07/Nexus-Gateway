"""Tests for message routing and envelope relay in the gateway."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from starlette.websockets import WebSocket, WebSocketState

from app.gateway.connection import ConnectionManager
from app.gateway.router import MessageRouter
from app.schemas.wire import RelayEnvelope
from tests.conftest import TestAgentIdentity


@pytest.mark.asyncio
async def test_online_routing_delivers_immediately(
    agent_alice: TestAgentIdentity,
    agent_bob: TestAgentIdentity,
    connection_manager: ConnectionManager,
    message_router: MessageRouter,
) -> None:
    """When recipient is online, message is routed directly via WebSocket."""
    # Connect Bob
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

    # Alice sends envelope to Bob
    envelope = agent_alice.make_envelope(recipient_id=agent_bob.agent_id)
    relay_frame = RelayEnvelope(
        relay_id="relay_12345",
        recipient=agent_bob.agent_id,
        envelope=envelope,
    )

    result = await message_router.handle_relay_envelope(
        relay_frame, sender_agent_id=agent_alice.agent_id
    )

    # Alice receives delivery_ack with delivered status
    assert result["type"] == "delivery_ack"
    assert result["relay_id"] == "relay_12345"
    assert result["status"] == "delivered"

    # Bob received the delivery frame with exact envelope intact
    assert len(bob_frames) == 1
    assert bob_frames[0]["type"] == "delivery"
    assert bob_frames[0]["relay_id"] == "relay_12345"
    assert bob_frames[0]["envelope"]["sender"] == agent_alice.agent_id
    assert bob_frames[0]["envelope"]["recipient"] == agent_bob.agent_id
    assert bob_frames[0]["envelope"]["message_id"] == envelope["message_id"]


@pytest.mark.asyncio
async def test_offline_routing_enqueues_message(
    agent_alice: TestAgentIdentity,
    agent_bob: TestAgentIdentity,
    message_router: MessageRouter,
) -> None:
    """When recipient is not connected, message is enqueued for offline delivery."""
    # Bob is not connected
    envelope = agent_alice.make_envelope(recipient_id=agent_bob.agent_id)
    relay_frame = RelayEnvelope(
        relay_id="relay_offline_1",
        recipient=agent_bob.agent_id,
        envelope=envelope,
    )

    result = await message_router.handle_relay_envelope(
        relay_frame, sender_agent_id=agent_alice.agent_id
    )

    assert result["type"] == "delivery_ack"
    assert result["relay_id"] == "relay_offline_1"
    assert result["status"] == "queued"


@pytest.mark.asyncio
async def test_duplicate_relay_id_deduplicated(
    agent_alice: TestAgentIdentity,
    agent_bob: TestAgentIdentity,
    message_router: MessageRouter,
) -> None:
    """Duplicate relay_id returns duplicate status without duplicate processing."""
    envelope = agent_alice.make_envelope(recipient_id=agent_bob.agent_id)
    relay_frame = RelayEnvelope(
        relay_id="relay_dup_test",
        recipient=agent_bob.agent_id,
        envelope=envelope,
    )

    res1 = await message_router.handle_relay_envelope(
        relay_frame, sender_agent_id=agent_alice.agent_id
    )
    assert res1["status"] == "queued"

    # Resend with same relay_id
    res2 = await message_router.handle_relay_envelope(
        relay_frame, sender_agent_id=agent_alice.agent_id
    )
    assert res2["status"] == "duplicate"


@pytest.mark.asyncio
async def test_spoofed_sender_rejected(
    agent_alice: TestAgentIdentity,
    agent_bob: TestAgentIdentity,
    agent_charlie: TestAgentIdentity,
    message_router: MessageRouter,
) -> None:
    """If authenticated agent_alice sends an envelope claiming sender is agent_charlie, reject."""
    # Charlie is sender in envelope, but Alice is the authenticated caller
    envelope = agent_charlie.make_envelope(recipient_id=agent_bob.agent_id)
    relay_frame = RelayEnvelope(
        relay_id="relay_spoof_1",
        recipient=agent_bob.agent_id,
        envelope=envelope,
    )

    result = await message_router.handle_relay_envelope(
        relay_frame, sender_agent_id=agent_alice.agent_id
    )

    assert result["type"] == "delivery_failed"
    assert "Sender mismatch" in result["reason"]
