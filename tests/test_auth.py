"""Tests for cryptographic challenge-response authentication in the gateway."""

from __future__ import annotations

import base64
from unittest.mock import AsyncMock

import pytest
from starlette.websockets import WebSocket, WebSocketState

from app.gateway.auth import (
    AuthenticationError,
    authenticate_websocket,
)
from app.security.crypto import (
    agent_id_from_public_key_b64,
    agent_id_matches_key,
    generate_challenge,
    verify_signature,
)
from tests.conftest import TestAgentIdentity


def test_crypto_fingerprint_and_verification(agent_alice: TestAgentIdentity) -> None:
    """Agent ID must be deterministic SHA-256 fingerprint, and signatures must verify."""
    # Correct key matches
    assert agent_id_matches_key(agent_alice.agent_id, agent_alice.public_key_b64)

    # Recomputed ID matches
    computed_id = agent_id_from_public_key_b64(agent_alice.public_key_b64)
    assert computed_id == agent_alice.agent_id

    # Signature verification
    challenge = generate_challenge(32)
    sig_b64 = agent_alice.sign(challenge)
    assert verify_signature(agent_alice.public_key_b64, challenge, sig_b64) is True

    # Tampered challenge fails
    tampered = challenge + b"tamper"
    assert verify_signature(agent_alice.public_key_b64, tampered, sig_b64) is False

    # Tampered signature fails
    bad_sig = base64.b64encode(b"X" * 64).decode("ascii")
    assert verify_signature(agent_alice.public_key_b64, challenge, bad_sig) is False


def test_crypto_mismatched_key_fails(
    agent_alice: TestAgentIdentity, agent_bob: TestAgentIdentity
) -> None:
    """Signature made with Alice's key must not verify under Bob's public key."""
    challenge = generate_challenge(32)
    alice_sig = agent_alice.sign(challenge)
    assert verify_signature(agent_bob.public_key_b64, challenge, alice_sig) is False


def test_crypto_spoofed_agent_id_detected(
    agent_alice: TestAgentIdentity, agent_bob: TestAgentIdentity
) -> None:
    """Claiming Alice's agent_id while presenting Bob's public key must be rejected."""
    # Alice's ID with Bob's key
    assert agent_id_matches_key(agent_alice.agent_id, agent_bob.public_key_b64) is False


@pytest.mark.asyncio
async def test_handshake_success(agent_alice: TestAgentIdentity) -> None:
    """Mock WebSocket handshake succeeds with valid credentials."""
    mock_ws = AsyncMock(spec=WebSocket)
    mock_ws.client_state = WebSocketState.CONNECTED

    sent_frames: list[dict] = []

    async def mock_send_json(data: dict) -> None:
        sent_frames.append(data)

    mock_ws.send_json.side_effect = mock_send_json

    async def mock_receive_json() -> dict:
        # Extract challenge sent in step 1
        challenge_frame = sent_frames[0]
        challenge_b64 = challenge_frame["challenge"]
        return agent_alice.make_auth_response(challenge_b64)

    mock_ws.receive_json.side_effect = mock_receive_json

    authed = await authenticate_websocket(mock_ws)

    assert authed.agent_id == agent_alice.agent_id
    assert authed.public_key == agent_alice.public_key_b64
    assert authed.display_name == "Alice"

    # Verify server sent auth_challenge and auth_result
    assert len(sent_frames) == 2
    assert sent_frames[0]["type"] == "auth_challenge"
    assert sent_frames[1]["type"] == "auth_result"
    assert sent_frames[1]["success"] is True


@pytest.mark.asyncio
async def test_handshake_bad_signature_rejected(
    agent_alice: TestAgentIdentity,
) -> None:
    """Handshake fails when signature is invalid."""
    mock_ws = AsyncMock(spec=WebSocket)
    mock_ws.client_state = WebSocketState.CONNECTED

    sent_frames: list[dict] = []
    mock_ws.send_json.side_effect = lambda data: sent_frames.append(data)

    async def mock_receive_json() -> dict:
        resp = agent_alice.make_auth_response("dGVzdA==")
        resp["signature"] = base64.b64encode(b"0" * 64).decode("ascii")
        return resp

    mock_ws.receive_json.side_effect = mock_receive_json

    with pytest.raises(AuthenticationError, match="Signature verification failed"):
        await authenticate_websocket(mock_ws)


@pytest.mark.asyncio
async def test_handshake_id_mismatch_rejected(
    agent_alice: TestAgentIdentity, agent_bob: TestAgentIdentity
) -> None:
    """Handshake fails when agent_id does not match public key fingerprint."""
    mock_ws = AsyncMock(spec=WebSocket)
    mock_ws.client_state = WebSocketState.CONNECTED

    sent_frames: list[dict] = []
    mock_ws.send_json.side_effect = lambda data: sent_frames.append(data)

    async def mock_receive_json() -> dict:
        resp = agent_bob.make_auth_response(sent_frames[0]["challenge"])
        # Spoof Alice's agent ID
        resp["agent_id"] = agent_alice.agent_id
        return resp

    mock_ws.receive_json.side_effect = mock_receive_json

    with pytest.raises(AuthenticationError, match="agent_id does not match"):
        await authenticate_websocket(mock_ws)
