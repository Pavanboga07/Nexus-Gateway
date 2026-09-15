"""Offline message queue with TTL and capacity enforcement.

When a message's recipient is offline, it is durably stored in the
gateway's PostgreSQL database and redelivered when the recipient
reconnects. Messages expire after ``message_ttl_seconds`` and are
periodically cleaned up.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from app.config import get_settings
from app.gateway.connection import ConnectionManager
from app.schemas.wire import Delivery
from app.storage.repository import GatewayRepository

logger = logging.getLogger(__name__)


class OfflineQueue:
    """Durable offline message queue backed by PostgreSQL."""

    def __init__(
        self,
        repository: GatewayRepository,
        connection_manager: ConnectionManager,
    ) -> None:
        self._repo = repository
        self._cm = connection_manager

    async def enqueue(
        self,
        relay_id: str,
        sender_id: str,
        recipient_id: str,
        envelope: dict,
    ) -> None:
        """Queue a message for offline delivery.

        Enforces per-agent queue capacity: if the queue is full, the
        oldest messages are evicted.
        """
        settings = get_settings()
        expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=settings.message_ttl_seconds
        )

        # Enforce queue capacity
        count = await self._repo.count_queued(recipient_id)
        if count >= settings.max_queue_per_agent:
            evicted = await self._repo.evict_oldest(
                recipient_id, keep=settings.max_queue_per_agent - 1
            )
            if evicted > 0:
                logger.warning(
                    "Evicted %d oldest messages from queue for %s",
                    evicted,
                    recipient_id,
                )

        await self._repo.enqueue_message(
            relay_id=relay_id,
            sender_id=sender_id,
            recipient_id=recipient_id,
            envelope=envelope,
            expires_at=expires_at,
        )
        await self._repo.log_delivery(
            relay_id=relay_id,
            sender_id=sender_id,
            recipient_id=recipient_id,
            status="queued",
        )
        logger.info(
            "Queued message %s for offline agent %s (expires %s)",
            relay_id,
            recipient_id,
            expires_at.isoformat(),
        )

    async def flush_to_agent(self, agent_id: str) -> int:
        """Deliver all queued messages to a now-online agent.

        Returns the number of messages successfully delivered.
        """
        messages = await self._repo.get_queued_messages(agent_id, limit=100)
        delivered_count = 0

        for msg in messages:
            delivery = Delivery(
                relay_id=msg.relay_id,
                envelope=msg.envelope_json,
            )
            success = await self._cm.send_to(
                agent_id, delivery.model_dump()
            )
            if success:
                await self._repo.mark_delivered(msg.relay_id)
                await self._repo.log_delivery(
                    relay_id=msg.relay_id,
                    sender_id=msg.sender_id,
                    recipient_id=msg.recipient_id,
                    status="delivered",
                )
                delivered_count += 1
                logger.debug(
                    "Flushed queued message %s to %s",
                    msg.relay_id,
                    agent_id,
                )
            else:
                logger.warning(
                    "Failed to flush message %s to %s — "
                    "agent may have disconnected again",
                    msg.relay_id,
                    agent_id,
                )
                break  # stop flushing if agent went offline again

        if delivered_count > 0:
            logger.info(
                "Flushed %d queued messages to %s", delivered_count, agent_id
            )
        return delivered_count

    async def cleanup_expired(self) -> int:
        """Remove all expired messages from the queue.

        Returns the number of messages removed.
        """
        count = await self._repo.cleanup_expired()
        if count > 0:
            logger.info("Cleaned up %d expired queued messages", count)
        return count


__all__ = ["OfflineQueue"]
