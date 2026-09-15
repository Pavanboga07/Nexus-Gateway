"""Challenge-response authentication for WebSocket connections.

The gateway never sees private keys. Authentication flow:

    1. Gateway generates a random 32-byte challenge
    2. Agent signs the challenge with its Ed25519 private key
    3. Gateway verifies:
       a) agent_id matches SHA-256 fingerprint of public_key
       b) signature over challenge is valid under public_key
    4. Connection is authenticated as agent_id

If any step fails, the connection is rejected with a structured error.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
from dataclasses import dataclass

from starlette.websockets import WebSocket, WebSocketState

from app.config import get_settings
from app.schemas.wire import (
    AuthChallenge,
    AuthResponse,
    AuthResult,
    GatewayError,
)
from app.security.crypto import (
    agent_id_matches_key,
    generate_challenge,
    verify_signature,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AuthenticatedAgent:
    """Result of a successful authentication handshake."""

    agent_id: str
    public_key: str  # base64 raw Ed25519 public key
    display_name: str | None


class AuthenticationError(Exception):
    """Raised when the authentication handshake fails."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


async def authenticate_websocket(ws: WebSocket) -> AuthenticatedAgent:
    """Run the challenge-response handshake on an accepted WebSocket.

    Raises ``AuthenticationError`` if the handshake fails or times out.
    The caller is responsible for closing the WebSocket on failure.
    """
    settings = get_settings()

    # --- Step 1: send challenge ---
    challenge_bytes = generate_challenge()
    challenge_b64 = base64.b64encode(challenge_bytes).decode("ascii")

    challenge_frame = AuthChallenge(challenge=challenge_b64)
    await ws.send_json(challenge_frame.model_dump())

    # --- Step 2: wait for auth_response ---
    try:
        raw = await asyncio.wait_for(
            ws.receive_json(),
            timeout=settings.auth_timeout_seconds,
        )
    except asyncio.TimeoutError:
        raise AuthenticationError("Authentication timed out.") from None
    except Exception as exc:
        raise AuthenticationError(
            f"Failed to receive auth response: {exc}"
        ) from None

    # --- Step 3: parse and validate ---
    if not isinstance(raw, dict):
        raise AuthenticationError("Expected JSON object for auth_response.")

    if raw.get("type") != "auth_response":
        raise AuthenticationError(
            f"Expected auth_response, got {raw.get('type', 'unknown')}."
        )

    try:
        response = AuthResponse.model_validate(raw)
    except Exception as exc:
        raise AuthenticationError(
            f"Malformed auth_response: {exc}"
        ) from None

    # --- Step 3a: verify agent_id matches public_key ---
    if not agent_id_matches_key(response.agent_id, response.public_key):
        raise AuthenticationError(
            "agent_id does not match the fingerprint of public_key."
        )

    # --- Step 3b: verify signature over challenge ---
    if not verify_signature(
        response.public_key, challenge_bytes, response.signature
    ):
        raise AuthenticationError(
            "Signature verification failed: the agent could not prove "
            "ownership of the claimed identity."
        )

    # --- Step 4: send success ---
    result = AuthResult(success=True, agent_id=response.agent_id)
    await ws.send_json(result.model_dump())

    logger.info(
        "Agent authenticated: %s (%s)",
        response.agent_id,
        response.display_name or "unnamed",
    )

    return AuthenticatedAgent(
        agent_id=response.agent_id,
        public_key=response.public_key,
        display_name=response.display_name,
    )


async def reject_websocket(
    ws: WebSocket, reason: str
) -> None:
    """Send an auth failure result and close the WebSocket."""
    try:
        if ws.client_state == WebSocketState.CONNECTED:
            result = AuthResult(success=False, error=reason)
            await ws.send_json(result.model_dump())
    except Exception:
        pass  # best-effort


__all__ = [
    "AuthenticatedAgent",
    "AuthenticationError",
    "authenticate_websocket",
    "reject_websocket",
]
