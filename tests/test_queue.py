"""Tests for offline message queue, capacity limits, and TTL expiry."""

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
    """Messages can be enqueued and retrieved for an offline recipient."""
    env1 = agent_alice.make_envelope(recipient_id=agent_bob.agent_id)
    env2 = agent_alice.make_envelope(recipient_id=agent_bob.agent_id)

    await offline_queue.enqueue("relay_q1", agent_alice.agent_id, agent_bob.agent_id, env1)
    await offline_queue.enqueue("relay_q2", agent_alice.agent_id, agent_bob.agent_id, env2)

    count = await repository.count_queued(agent_bob.agent_id)
    assert count == 2

    messages = await repository.get_queued_messages(agent_bob.agent_id)
    assert len(messages) == 2
    assert messages[0].relay_id == "relay_q1"
    assert messages[1].relay_id == "relay_q2"
    assert messages[0].delivered is False


@pytest.mark.asyncio
async def test_queue_capacity_evicts_oldest(
    agent_alice: TestAgentIdentity,
    agent_bob: TestAgentIdentity,
    repository: GatewayRepository,
) -> None:
    """When queue exceeds capacity, oldest undelivered messages are evicted."""
    now = datetime.now(timezone.utc)
    future = now + timedelta(hours=1)

    for i in range(5):
        env = agent_alice.make_envelope(recipient_id=agent_bob.agent_id)
        await repository.enqueue_message(
            relay_id=f"relay_cap_{i}",
            sender_id=agent_alice.agent_id,
            recipient_id=agent_bob.agent_id,
            envelope=env,
            expires_at=future,
        )

    assert await repository.count_queued(agent_bob.agent_id) == 5

    # Evict down to keeping 3
    evicted = await repository.evict_oldest(agent_bob.agent_id, keep=3)
    assert evicted == 2
    assert await repository.count_queued(agent_bob.agent_id) == 3

    remaining = await repository.get_queued_messages(agent_bob.agent_id)
    # The oldest (relay_cap_0 and relay_cap_1) should have been evicted
    remaining_ids = [m.relay_id for m in remaining]
    assert remaining_ids == ["relay_cap_2", "relay_cap_3", "relay_cap_4"]


@pytest.mark.asyncio
async def test_queue_cleanup_expired(
    agent_alice: TestAgentIdentity,
    agent_bob: TestAgentIdentity,
    repository: GatewayRepository,
    offline_queue: OfflineQueue,
) -> None:
    """Expired messages are purged by cleanup."""
    now = datetime.now(timezone.utc)
    past = now - timedelta(minutes=10)
    future = now + timedelta(hours=1)

    env = agent_alice.make_envelope(recipient_id=agent_bob.agent_id)
    # 1 expired message
    await repository.enqueue_message(
        relay_id="relay_expired_1",
        sender_id=agent_alice.agent_id,
        recipient_id=agent_bob.agent_id,
        envelope=env,
        expires_at=past,
    )
    # 1 valid message
    await repository.enqueue_message(
        relay_id="relay_valid_1",
        sender_id=agent_alice.agent_id,
        recipient_id=agent_bob.agent_id,
        envelope=env,
        expires_at=future,
    )

    cleaned = await offline_queue.cleanup_expired()
    assert cleaned == 1

    remaining = await repository.get_queued_messages(agent_bob.agent_id)
    assert len(remaining) == 1
    assert remaining[0].relay_id == "relay_valid_1"
