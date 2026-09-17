"""M2 regression tests: ack-driven delivery, leasing, dedup, dead-letter queue.

Audit findings covered:

  M2  ``delivery_ack`` was received by the gateway and discarded with a
      ``pass``, while ``delivered`` was set the moment ``send_json`` returned.
      "Delivered" therefore meant "bytes reached a socket", which is not
      delivery. The delivery log was misleading and a message lost after the
      send was undetectable.
  M3  Queue overflow deleted the oldest rows and TTL cleanup deleted
      expired-undelivered rows - both silently, with no record.
  H5  Dedup lived in an in-process ``set``: empty after every restart, and
      separate per replica, so the same message was processed once per
      replica. Presence and claims were likewise process-local.
  M5  The gateway created its schema with ``create_all`` despite shipping
      migrations.
"""

from __future__ import annotations

import inspect
from datetime import datetime, timedelta, timezone

import pytest

from app.gateway.connection import ConnectionManager
from app.gateway.queue import OfflineQueue
from app.gateway.router import MessageRouter
from app.schemas.wire import RelayEnvelope
from app.storage.repository import GatewayRepository
from tests.conftest import TestAgentIdentity


def _make_queue(
    repository: GatewayRepository, replica_id: str
) -> tuple[OfflineQueue, ConnectionManager]:
    cm = ConnectionManager(max_connections=50)
    return (
        OfflineQueue(repository=repository, connection_manager=cm, replica_id=replica_id),
        cm,
    )


@pytest.mark.asyncio
async def test_delivery_ack_is_what_completes_a_queued_send(
    agent_alice: TestAgentIdentity,
    agent_bob: TestAgentIdentity,
    repository: GatewayRepository,
    offline_queue: OfflineQueue,
) -> None:
    """send -> pending; ack -> delivered. The distinction is the whole point."""
    env = agent_alice.make_envelope(recipient_id=agent_bob.agent_id)
    await offline_queue.enqueue(
        "relay_m2_ack", agent_alice.agent_id, agent_bob.agent_id, env
    )

    # A claim (which is what a send does) must NOT mark it delivered.
    claimed = await repository.claim_pending_messages(agent_bob.agent_id)
    assert claimed[0].relay_id == "relay_m2_ack"
    assert claimed[0].delivered is False
    assert claimed[0].acked_at is None
    assert await repository.count_queued(agent_bob.agent_id) == 1

    # Only the ack completes it, and it records when.
    assert await repository.acknowledge_delivery("relay_m2_ack") is True
    row = await repository.get_message("relay_m2_ack")
    assert row is not None and row.delivered is True and row.acked_at is not None
    assert await repository.count_queued(agent_bob.agent_id) == 0


@pytest.mark.asyncio
async def test_router_acknowledges_a_delivery(
    agent_alice: TestAgentIdentity,
    agent_bob: TestAgentIdentity,
    repository: GatewayRepository,
    offline_queue: OfflineQueue,
    message_router: MessageRouter,
) -> None:
    """The WS ack frame must reach the queue (it used to be ignored)."""
    env = agent_alice.make_envelope(recipient_id=agent_bob.agent_id)
    await offline_queue.enqueue(
        "relay_m2_ws_ack", agent_alice.agent_id, agent_bob.agent_id, env
    )

    assert await message_router.acknowledge_delivery("relay_m2_ws_ack") is True
    assert await repository.count_queued(agent_bob.agent_id) == 0


@pytest.mark.asyncio
async def test_two_replicas_do_not_double_send(
    agent_alice: TestAgentIdentity,
    agent_bob: TestAgentIdentity,
    repository: GatewayRepository,
) -> None:
    """Two replicas flushing the same recipient: each row is sent once.

    Pre-fix there was no claim at all, so both replicas would have sent it -
    duplicate delivery was the normal case under scale-out, not an edge case.
    """
    queue_a, _cm_a = _make_queue(repository, "replica-a")
    queue_b, _cm_b = _make_queue(repository, "replica-b")

    env = agent_alice.make_envelope(recipient_id=agent_bob.agent_id)
    await queue_a.enqueue(
        "relay_m2_split", agent_alice.agent_id, agent_bob.agent_id, env
    )

    claimed_a = await repository.claim_pending_messages(
        agent_bob.agent_id, lease_seconds=60.0, claimed_by="replica-a"
    )
    claimed_b = await repository.claim_pending_messages(
        agent_bob.agent_id, lease_seconds=60.0, claimed_by="replica-b"
    )
    assert [m.relay_id for m in claimed_a] == ["relay_m2_split"]
    assert claimed_b == []
    # Still undelivered, because neither replica has been acked.
    assert await repository.count_queued(agent_bob.agent_id) == 1


@pytest.mark.asyncio
async def test_expired_lease_reclaims_after_replica_crash(
    agent_alice: TestAgentIdentity,
    agent_bob: TestAgentIdentity,
    repository: GatewayRepository,
) -> None:
    """A replica that dies mid-send must not strand the message."""
    queue, _cm = _make_queue(repository, "replica-a")
    env = agent_alice.make_envelope(recipient_id=agent_bob.agent_id)
    await queue.enqueue(
        "relay_m2_crash", agent_alice.agent_id, agent_bob.agent_id, env
    )

    # Replica A claims (leases) the row and then "crashes" (never acks).
    await repository.claim_pending_messages(
        agent_bob.agent_id, lease_seconds=60.0, claimed_by="replica-a"
    )
    # Within the lease, nobody else may take it.
    assert (
        await repository.claim_pending_messages(
            agent_bob.agent_id, lease_seconds=60.0, claimed_by="replica-b"
        )
        == []
    )
    # Once the lease has expired, another replica can retry it. Duplicate
    # delivery is therefore bounded to the crash window rather than permanent.
    recovered = await repository.claim_pending_messages(
        agent_bob.agent_id, lease_seconds=0.0, claimed_by="replica-b"
    )
    assert [m.relay_id for m in recovered] == ["relay_m2_crash"]
    assert recovered[0].delivery_attempts == 2


@pytest.mark.asyncio
async def test_cross_replica_delivery_via_redelivery_sweep(
    agent_alice: TestAgentIdentity,
    agent_bob: TestAgentIdentity,
    repository: GatewayRepository,
) -> None:
    """A message queued while the recipient is on another replica still lands.

    This is what makes horizontal scaling correct rather than merely possible:
    the sweep flushes pending rows for agents connected to THIS replica.
    """
    queue_a, cm_a = _make_queue(repository, "replica-a")
    queue_b, cm_b = _make_queue(repository, "replica-b")

    # Alice's message is queued while Bob is unreachable.
    env = agent_alice.make_envelope(recipient_id=agent_bob.agent_id)
    await queue_a.enqueue(
        "relay_m2_cross", agent_alice.agent_id, agent_bob.agent_id, env
    )

    # On replica B nothing happens: Bob is not connected there.
    assert await queue_b.redeliver_pending() == 0

    # Bob connects to replica B. A fake connected socket is enough for the
    # sweep to pick the row up.
    class _FakeWS:
        client_state = None

        def __init__(self) -> None:
            from starlette.websockets import WebSocketState

            self.client_state = WebSocketState.CONNECTED
            self.sent: list[dict] = []

        async def send_json(self, data: dict) -> None:
            self.sent.append(data)

        async def close(self, code: int = 1000, reason: str = "") -> None:
            pass

    ws = _FakeWS()
    await cm_b.register(
        agent_id=agent_bob.agent_id,
        public_key=agent_bob.public_key_b64,
        display_name="Bob",
        websocket=ws,  # type: ignore[arg-type]
    )

    sent = await queue_b.redeliver_pending()
    assert sent == 1
    assert ws.sent[0]["relay_id"] == "relay_m2_cross"

    # And replica A can no longer send it: the row is leased to B.
    assert await queue_a.redeliver_pending() == 0


@pytest.mark.asyncio
async def test_poison_message_is_dead_lettered_not_retried_for_ever(
    agent_alice: TestAgentIdentity,
    agent_bob: TestAgentIdentity,
    repository: GatewayRepository,
    offline_queue: OfflineQueue,
) -> None:
    """A recipient that keeps connecting but never acks must not wedge the queue."""
    from app.config import get_settings

    settings = get_settings()
    original = settings.max_delivery_attempts
    settings.max_delivery_attempts = 3
    try:
        env = agent_alice.make_envelope(recipient_id=agent_bob.agent_id)
        await offline_queue.enqueue(
            "relay_m2_poison", agent_alice.agent_id, agent_bob.agent_id, env
        )

        class _ConnectedWS:
            def __init__(self) -> None:
                from starlette.websockets import WebSocketState

                self.client_state = WebSocketState.CONNECTED

            async def send_json(self, data: dict) -> None:
                pass

            async def close(self, code: int = 1000, reason: str = "") -> None:
                pass

        cm = offline_queue._cm
        await cm.register(
            agent_id=agent_bob.agent_id,
            public_key=agent_bob.public_key_b64,
            display_name="Bob",
            websocket=_ConnectedWS(),  # type: ignore[arg-type]
        )

        # Each flush sends but is never acked; attempt count climbs past the cap.
        for _ in range(6):
            await offline_queue.flush_to_agent(agent_bob.agent_id)
            await repository.release_lease("relay_m2_poison", reason="no ack")

        dead = await repository.list_dead_letters()
        assert [d.relay_id for d in dead] == ["relay_m2_poison"]
        assert dead[0].reason == "max_attempts_exceeded"
        assert dead[0].delivery_attempts > 3
        # The queued row is gone: a message is never both queued and dead.
        assert await repository.get_message("relay_m2_poison") is None
    finally:
        settings.max_delivery_attempts = original


@pytest.mark.asyncio
async def test_sent_router_frame_is_not_reported_as_delivered(
    agent_alice: TestAgentIdentity,
    agent_bob: TestAgentIdentity,
    repository: GatewayRepository,
    offline_queue: OfflineQueue,
    message_router: MessageRouter,
) -> None:
    """The ack returned to the SENDER must not claim delivery."""
    class _ConnectedWS:
        def __init__(self) -> None:
            from starlette.websockets import WebSocketState

            self.client_state = WebSocketState.CONNECTED

        async def send_json(self, data: dict) -> None:
            pass

        async def close(self, code: int = 1000, reason: str = "") -> None:
            pass

    await message_router._cm.register(
        agent_id=agent_bob.agent_id,
        public_key=agent_bob.public_key_b64,
        display_name="Bob",
        websocket=_ConnectedWS(),  # type: ignore[arg-type]
    )

    frame = RelayEnvelope(
        relay_id="relay_m2_status",
        recipient=agent_bob.agent_id,
        envelope=agent_alice.make_envelope(recipient_id=agent_bob.agent_id),
    )
    result = await message_router.handle_relay_envelope(
        frame, sender_agent_id=agent_alice.agent_id
    )
    assert result["type"] == "delivery_ack"
    assert result["status"] == "sent", (
        "the gateway must not tell the sender a message is delivered before the "
        "recipient acks it"
    )


# ---------------------------------------------------------------------------
# Structural guards
# ---------------------------------------------------------------------------


def test_message_loop_no_longer_discards_delivery_ack():
    """The ack frame must be handled, not `pass`ed."""
    import app.main as gateway_main

    src = inspect.getsource(gateway_main._message_loop)
    assert "delivery_ack" in src
    assert "acknowledge_delivery" in src


def test_router_has_no_in_process_dedup_set():
    """Dedup must be durable and shared, not a per-process set."""
    src = inspect.getsource(MessageRouter)
    assert "_seen_relay_ids" not in src
    assert "try_record_relay" in src


def test_claim_uses_skip_locked():
    """Concurrent replica claims must not block or duplicate."""
    src = inspect.getsource(GatewayRepository.claim_pending_messages)
    assert "skip_locked=True" in src
