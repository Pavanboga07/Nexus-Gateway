"""Tests for the at-least-once outbox: capacity, TTL, ack semantics, DLQ.

Semantics changed in M2: a message is delivered only when the recipient ACKS.
These tests pin that, plus the dead-letter behaviour that replaced silent
deletion on overflow and TTL expiry.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.gateway.connection import ConnectionManager
from app.gateway.queue import OfflineQueue
from app.storage.repository import GatewayRepository
from tests.conftest import TestAgentIdentity


@pytest.mark.asyncio
async def test_queue_and_count(
    agent_alice: TestAgentIdentity,
    agent_bob: TestAgentIdentity,
    offline_queue: OfflineQueue,
    repository: GatewayRepository,
) -> None:
    """Messages can be enqueued and claimed (oldest first) for a recipient."""
    env1 = agent_alice.make_envelope(recipient_id=agent_bob.agent_id)
    env2 = agent_alice.make_envelope(recipient_id=agent_bob.agent_id)

    await offline_queue.enqueue("relay_q1", agent_alice.agent_id, agent_bob.agent_id, env1)
    await offline_queue.enqueue("relay_q2", agent_alice.agent_id, agent_bob.agent_id, env2)

    count = await repository.count_queued(agent_bob.agent_id)
    assert count == 2

    # claim_pending_messages replaces get_queued_messages: claiming leases the
    # rows, which is what makes concurrent flushes safe.
    claimed = await repository.claim_pending_messages(agent_bob.agent_id)
    assert [m.relay_id for m in claimed] == ["relay_q1", "relay_q2"]
    assert all(m.delivered is False for m in claimed)
    # A claim increments the attempt counter.
    assert all(m.delivery_attempts == 1 for m in claimed)


@pytest.mark.asyncio
async def test_queue_capacity_evicts_oldest_to_dead_letter(
    agent_alice: TestAgentIdentity,
    agent_bob: TestAgentIdentity,
    repository: GatewayRepository,
    offline_queue: OfflineQueue,
    monkeypatch,
) -> None:
    """Overflow drops the OLDEST messages, and records them in the DLQ.

    Pre-fix overflow deleted rows outright, so the loss left no trace at all.
    """
    from app.config import get_settings
    from app.storage import repository as repo_module

    # get_settings() caches its instance, so patching the class default is not
    # enough - patch the cached object's attribute and restore it afterwards.
    settings = get_settings()
    monkeypatch.setattr(settings, "max_queue_per_agent", 3)

    now = datetime.now(timezone.utc)
    future = now + timedelta(hours=1)

    # Enqueue 5 through the queue (which enforces capacity), not the repo.
    for i in range(5):
        env = agent_alice.make_envelope(recipient_id=agent_bob.agent_id)
        await offline_queue.enqueue(
            f"relay_cap_{i}", agent_alice.agent_id, agent_bob.agent_id, env
        )

    remaining = await repository.claim_pending_messages(agent_bob.agent_id, limit=100)
    remaining_ids = [m.relay_id for m in remaining]
    # Capacity is 3, so the two oldest were removed.
    assert len(remaining_ids) == 3
    assert remaining_ids == ["relay_cap_2", "relay_cap_3", "relay_cap_4"]

    # ...and the evicted ones are recoverable from the dead-letter queue.
    dead = await repository.list_dead_letters()
    dead_ids = sorted(d.relay_id for d in dead)
    assert dead_ids == ["relay_cap_0", "relay_cap_1"]
    assert all(d.reason == "queue_overflow" for d in dead)


@pytest.mark.asyncio
async def test_queue_cleanup_expired_dead_letters_undelivered(
    agent_alice: TestAgentIdentity,
    agent_bob: TestAgentIdentity,
    repository: GatewayRepository,
    offline_queue: OfflineQueue,
) -> None:
    """Expiring without delivery is a failure, so it is recorded, not dropped."""
    now = datetime.now(timezone.utc)
    past = now - timedelta(minutes=10)
    future = now + timedelta(hours=1)

    env = agent_alice.make_envelope(recipient_id=agent_bob.agent_id)
    await repository.enqueue_message(
        relay_id="relay_expired_1",
        sender_id=agent_alice.agent_id,
        recipient_id=agent_bob.agent_id,
        envelope=env,
        expires_at=past,
    )
    await repository.enqueue_message(
        relay_id="relay_valid_1",
        sender_id=agent_alice.agent_id,
        recipient_id=agent_bob.agent_id,
        envelope=env,
        expires_at=future,
    )

    cleaned = await offline_queue.cleanup_expired()
    assert cleaned == 1

    remaining = await repository.claim_pending_messages(agent_bob.agent_id, limit=100)
    assert [m.relay_id for m in remaining] == ["relay_valid_1"]

    dead = await repository.list_dead_letters()
    assert [d.relay_id for d in dead] == ["relay_expired_1"]
    assert dead[0].reason == "expired_undelivered"


@pytest.mark.asyncio
async def test_ack_is_what_marks_a_message_delivered(
    agent_alice: TestAgentIdentity,
    agent_bob: TestAgentIdentity,
    repository: GatewayRepository,
    offline_queue: OfflineQueue,
) -> None:
    """Sending is not delivering: only an ack sets `delivered`."""
    env = agent_alice.make_envelope(recipient_id=agent_bob.agent_id)
    await offline_queue.enqueue(
        "relay_ack_1", agent_alice.agent_id, agent_bob.agent_id, env
    )

    claimed = await repository.claim_pending_messages(agent_bob.agent_id)
    assert claimed[0].delivered is False

    # Without an ack the row is still pending (it will be retried).
    assert await repository.count_queued(agent_bob.agent_id) == 1

    # The ack is what completes it.
    assert await offline_queue.acknowledge("relay_ack_1") is True
    assert await repository.count_queued(agent_bob.agent_id) == 0

    row = await repository.get_message("relay_ack_1")
    assert row is not None
    assert row.delivered is True
    assert row.acked_at is not None

    # Acking twice is harmless (idempotent), and acking an unknown id is not an
    # error either - a reaped row should not break a reconnecting client.
    assert await offline_queue.acknowledge("relay_ack_1") is False
    assert await offline_queue.acknowledge("relay_does_not_exist") is False


@pytest.mark.asyncio
async def test_claim_is_exclusive_and_lease_expiry_frees_the_row(
    agent_alice: TestAgentIdentity,
    agent_bob: TestAgentIdentity,
    repository: GatewayRepository,
    offline_queue: OfflineQueue,
) -> None:
    """Two replicas must not claim the same row; a stale lease must expire.

    This is the property that makes more than one gateway replica safe.
    """
    env = agent_alice.make_envelope(recipient_id=agent_bob.agent_id)
    await offline_queue.enqueue(
        "relay_lease_1", agent_alice.agent_id, agent_bob.agent_id, env
    )

    first = await repository.claim_pending_messages(
        agent_bob.agent_id, lease_seconds=60.0, claimed_by="replica-1"
    )
    assert len(first) == 1
    assert first[0].claimed_by == "replica-1"

    # A second replica gets nothing while the lease is held.
    second = await repository.claim_pending_messages(
        agent_bob.agent_id, lease_seconds=60.0, claimed_by="replica-2"
    )
    assert second == []

    # Once the lease has aged out (simulated by leasing with lease_seconds=0),
    # the row becomes claimable again so a crashed replica cannot strand it.
    third = await repository.claim_pending_messages(
        agent_bob.agent_id, lease_seconds=0.0, claimed_by="replica-2"
    )
    assert len(third) == 1
    assert third[0].claimed_by == "replica-2"
    assert third[0].delivery_attempts == 2


@pytest.mark.asyncio
async def test_release_lease_returns_row_to_pending(
    agent_alice: TestAgentIdentity,
    agent_bob: TestAgentIdentity,
    repository: GatewayRepository,
    offline_queue: OfflineQueue,
) -> None:
    """A failed send releases the lease so the message stays retryable."""
    env = agent_alice.make_envelope(recipient_id=agent_bob.agent_id)
    await offline_queue.enqueue(
        "relay_release_1", agent_alice.agent_id, agent_bob.agent_id, env
    )

    claimed = await repository.claim_pending_messages(
        agent_bob.agent_id, claimed_by="replica-1"
    )
    assert len(claimed) == 1
    await repository.release_lease("relay_release_1", reason="send_failed")

    again = await repository.claim_pending_messages(
        agent_bob.agent_id, claimed_by="replica-1"
    )
    assert len(again) == 1
    assert await repository.count_queued(agent_bob.agent_id) == 1


@pytest.mark.asyncio
async def test_relay_id_dedup_is_durable_and_shared(
    agent_alice: TestAgentIdentity,
    agent_bob: TestAgentIdentity,
    repository: GatewayRepository,
) -> None:
    """Dedup survives a new repository instance (i.e. a restart or a replica)."""
    first = await repository.try_record_relay(
        relay_id="relay_dedup_1",
        sender_id=agent_alice.agent_id,
        recipient_id=agent_bob.agent_id,
    )
    assert first is True

    # A DIFFERENT GatewayRepository instance represents another replica / a
    # restarted process. The old in-process set would have said "new" here.
    other_repo = GatewayRepository(session_factory=repository._session_factory)
    second = await other_repo.try_record_relay(
        relay_id="relay_dedup_1",
        sender_id=agent_alice.agent_id,
        recipient_id=agent_bob.agent_id,
    )
    assert second is False


@pytest.mark.asyncio
async def test_dead_letter_is_bounded_and_prunable(
    agent_alice: TestAgentIdentity,
    agent_bob: TestAgentIdentity,
    repository: GatewayRepository,
) -> None:
    """Dedup + DLQ tables have retention paths (they must not grow for ever)."""
    await repository.try_record_relay(
        relay_id="relay_prune_1",
        sender_id=agent_alice.agent_id,
        recipient_id=agent_bob.agent_id,
    )
    pruned = await repository.prune_processed_relays(
        older_than=datetime.now(timezone.utc) + timedelta(seconds=1)
    )
    assert pruned == 1

    await repository.move_to_dead_letter(
        relay_id="relay_dl_1",
        sender_id=agent_alice.agent_id,
        recipient_id=agent_bob.agent_id,
        reason="test",
        envelope={"k": "v"},
        detail=None,
        delivery_attempts=3,
    )
    assert await repository.dead_letter_depth() == 1
    dead = await repository.list_dead_letters()
    assert dead[0].delivery_attempts == 3
