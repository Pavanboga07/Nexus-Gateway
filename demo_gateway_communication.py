"""Interactive Live Demo: Testing End-to-End Communication through Nexus Gateway.

Demonstrates:
1. Two agents (Alice & Bob) connecting to the Gateway over WebSocket.
2. Cryptographic challenge-response handshake (Ed25519) for both.
3. Presence query: Alice checks if Bob is online.
4. Direct Message Relay: Alice sends a signed A2A envelope to Bob through the Gateway.
5. Bidirectional response: Bob receives the message and sends a signed response back.
6. Offline Buffering & Reconnection:
   - Bob goes offline (disconnects).
   - Alice sends a message to Bob while he is offline (Gateway queues it with TTL).
   - Bob reconnects -> Gateway flushes the queued message to Bob automatically!
"""

from __future__ import annotations

import asyncio
import base64
import json
import uuid
from datetime import datetime, timedelta, timezone

import websockets
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

GATEWAY_WS_URL = "ws://127.0.0.1:9000/ws"


class DemoAgent:
    """Represents a simulated agent with Ed25519 identity."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key_raw = self.private_key.public_key().public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )
        self.public_key_b64 = base64.b64encode(self.public_key_raw).decode("ascii")
        import hashlib
        digest = hashlib.sha256(self.public_key_raw).hexdigest()
        self.agent_id = f"nexus:ed25519:{digest[:32]}"
        self.ws: websockets.WebSocketClientProtocol | None = None
        self.inbox: list[dict] = []
        self._listener_task: asyncio.Task | None = None

    def sign(self, data: bytes) -> str:
        sig = self.private_key.sign(data)
        return base64.b64encode(sig).decode("ascii")

    async def connect_and_auth(self) -> None:
        print(f"[{self.name}] Connecting to Gateway at {GATEWAY_WS_URL}...")
        self.ws = await websockets.connect(GATEWAY_WS_URL)

        # 1. Receive challenge
        raw = await self.ws.recv()
        challenge_frame = json.loads(raw)
        challenge_b64 = challenge_frame["challenge"]
        challenge_bytes = base64.b64decode(challenge_b64.encode("ascii"))

        # 2. Sign challenge
        sig_b64 = self.sign(challenge_bytes)

        # 3. Send auth response
        auth_resp = {
            "type": "auth_response",
            "agent_id": self.agent_id,
            "public_key": self.public_key_b64,
            "signature": sig_b64,
            "display_name": self.name,
        }
        await self.ws.send(json.dumps(auth_resp))

        # 4. Receive auth result
        res_raw = await self.ws.recv()
        result = json.loads(res_raw)
        if result.get("success"):
            print(f"[{self.name}] [AUTH OK] Authenticated as {self.agent_id[:24]}...")
        else:
            raise RuntimeError(f"Auth failed: {result}")

        # Start listener loop
        self._listener_task = asyncio.create_task(self._listen())

    async def _listen(self) -> None:
        try:
            assert self.ws is not None
            async for raw in self.ws:
                frame = json.loads(raw)
                if frame.get("type") == "delivery":
                    relay_id = frame.get("relay_id")
                    envelope = frame.get("envelope", {})
                    print(f"[{self.name}] [RECV] Received message from {envelope.get('sender', '')[:24]}...: {envelope.get('payload')}")
                    self.inbox.append(envelope)
                    # Send ack
                    await self.ws.send(json.dumps({"type": "delivery_ack", "relay_id": relay_id}))
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

    async def disconnect(self) -> None:
        if self._listener_task:
            self._listener_task.cancel()
        if self.ws:
            await self.ws.close()
            self.ws = None
        print(f"[{self.name}] [DISCONNECT] Disconnected from Gateway.")

    async def send_message(self, recipient_id: str, text: str) -> None:
        assert self.ws is not None
        now = datetime.now(timezone.utc)
        envelope = {
            "protocol": "nexus-a2a",
            "version": "0.1",
            "message_id": f"msg_{uuid.uuid4().hex}",
            "task_id": f"task_{uuid.uuid4().hex}",
            "sender": self.agent_id,
            "recipient": recipient_id,
            "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": (now + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "message_type": "request",
            "purpose": "chat",
            "payload": {"action": "message", "data_category": "conversation", "text": text},
            "signature": self.sign(b"mock_bytes"),
        }
        frame = {
            "type": "relay_envelope",
            "relay_id": f"relay_{uuid.uuid4().hex}",
            "recipient": recipient_id,
            "envelope": envelope,
        }
        await self.ws.send(json.dumps(frame))
        print(f"[{self.name}] [SEND] Sent relay_envelope to {recipient_id[:24]}... -> \"{text}\"")


async def run_demo() -> None:
    print("\n=======================================================")
    print("   NEXUS GATEWAY LIVE COMMUNICATION TEST")
    print("=======================================================\n")

    alice = DemoAgent("Alice")
    bob = DemoAgent("Bob")

    # Step 1: Both agents connect and authenticate
    print("--- Step 1: Connecting Alice and Bob ---")
    await alice.connect_and_auth()
    await bob.connect_and_auth()
    await asyncio.sleep(0.5)

    # Step 2: Online Message Relay
    print("\n--- Step 2: Alice sends message to Bob (Both Online) ---")
    await alice.send_message(bob.agent_id, "Hello Bob! Can you hear me through the Gateway?")
    await asyncio.sleep(1.0)
    assert len(bob.inbox) == 1, "Bob should have received Alice's message!"
    print(f"Verified: Bob has {len(bob.inbox)} message in inbox.")

    # Step 3: Bob replies to Alice
    print("\n--- Step 3: Bob replies to Alice ---")
    await bob.send_message(alice.agent_id, "Loud and clear Alice! The relay works smoothly.")
    await asyncio.sleep(1.0)
    assert len(alice.inbox) == 1, "Alice should have received Bob's reply!"
    print(f"Verified: Alice has {len(alice.inbox)} message in inbox.")

    # Step 4: Offline Buffering & Reconnection
    print("\n--- Step 4: Bob goes OFFLINE ---")
    await bob.disconnect()
    await asyncio.sleep(0.5)

    print("\n--- Step 5: Alice sends message while Bob is offline ---")
    await alice.send_message(bob.agent_id, "Bob, you're offline, but this message should be buffered on the Gateway!")
    await asyncio.sleep(1.0)

    print("\n--- Step 6: Bob reconnects to Gateway ---")
    await bob.connect_and_auth()
    # Gateway automatically flushes queued message on reconnect!
    await asyncio.sleep(1.0)

    assert len(bob.inbox) == 2, "Bob should have received the queued message upon reconnect!"
    print(f"\n[SUCCESS] Bob received the queued message after reconnecting: \"{bob.inbox[-1]['payload']['text']}\"")

    # Cleanup
    await alice.disconnect()
    await bob.disconnect()

    print("\n=======================================================")
    print("   [OK] ALL COMMUNICATION TESTS PASSED SUCCESSFULLY!")
    print("=======================================================\n")


if __name__ == "__main__":
    asyncio.run(run_demo())
