"""Offline/at-least-once outbox with TTL, leases, capacity and a DLQ.

Delivery semantics (M2)
-----------------------
A queued message is considered delivered **only when the recipient's client
acks it** (``delivery_ack``). Previously the gateway marked a message
delivered the moment ``send_json`` returned, which means "bytes reached a
socket", not "the agent received it" - and ``delivery_ack``, which the client
already sends, was discarded with a ``pass``.

Concretely:

  * ``flush_to_agent`` leases rows (``FOR UPDATE SKIP LOCKED``) so two replicas
    flushing the same recipient cannot both send the same row.
  * A lease expires, so a replica that crashes mid-send does not strand the
    message for ever. Duplicate delivery is therefore bounded to the crash
    window rather than being the normal case.
  * Rows that keep failing (recipient connects but never acks, or sends keep
    erroring) are moved to the dead-letter queue after
    ``max_delivery_attempts`` instead of being retried for ever.
  * Expiring undelivered messages are dead-lettered rather than silently
    dropped, because a TTL expiry on an undelivered message is a failure worth
    recording.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone

from app.config import get_settings
from app.gateway.connection import ConnectionManager
from app.schemas.wire import Delivery
from app.storage.repository import GatewayRepository

logger = logging.getLogger(__name__)


class OfflineQueue:
    """Durable at-least-once outbox backed by PostgreSQL."""

    def __init__(
        self,
        repository: GatewayRepository,
        connection_manager: ConnectionManager,
        *,
        replica_id: str | None = None,
    ) -> None:
        self._repo = repository
        self._cm = connection_manager
        #: Distinguishes this replica's leases in diagnostics.
        self._replica_id = replica_id or f"gw-{uuid.uuid4().hex[:8]}"

    @property
    def replica_id(self) -> str:
        return self._replica_id

    async def enqueue(
        self,
        relay_id: str,
        sender_id: str,
        recipient_id: str,
        envelope: dict,
    ) -> None:
        """Queue a message for later delivery.

        Enforces per-agent capacity: when a recipient's queue is full the
        OLDEST messages are evicted **to the dead-letter queue** (previously
        they were deleted outright, so the loss was invisible).
        """
        settings = get_settings()
        expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=settings.message_ttl_seconds
        )

        count = await self._repo.count_queued(recipient_id)
        if count >= settings.max_queue_per_agent:
            evicted = await self._evict_oldest_to_dlq(
                recipient_id, keep=settings.max_queue_per_agent - 1
            )
            if evicted > 0:
                logger.warning(
                    "Queue full for %s: dead-lettered %d oldest message(s)",
                    recipient_id,
                    evicted,
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

    async def _evict_oldest_to_dlq(self, recipient_id: str, *, keep: int) -> int:
        """Dead-letter the oldest pending rows beyond ``keep``.

        Uses a NON-leasing listing on purpose: leasing here would leave a lease
        on the rows we keep, hiding them from the delivery path until the lease
        expired.
        """
        rows = await self._repo.list_pending_for_recipient(recipient_id)
        remove = rows[: max(0, len(rows) - keep)]
        for row in remove:
            await self._repo.move_to_dead_letter(
                relay_id=row.relay_id,
                sender_id=row.sender_id,
                recipient_id=row.recipient_id,
                reason="queue_overflow",
                envelope=row.envelope_json,
                detail=(
                    f"recipient queue exceeded max_queue_per_agent; "
                    f"{row.delivery_attempts} prior attempt(s)"
                ),
                delivery_attempts=row.delivery_attempts,
            )
        return len(remove)

    async def flush_to_agent(self, agent_id: str, *, limit: int = 100) -> int:
        """Lease and send pending messages to a now-online agent.

        Returns the number of messages *sent* (not acked). Delivery is
        confirmed later by ``acknowledge``. Ordering is preserved per
        recipient because rows are claimed oldest-first and we stop on the
        first send failure.
        """
        settings = get_settings()
        max_attempts = settings.max_delivery_attempts
        messages = await self._repo.claim_pending_messages(
            agent_id,
            limit=limit,
            lease_seconds=settings.delivery_lease_seconds,
            claimed_by=self._replica_id,
        )

        sent_count = 0
        for msg in messages:
            if msg.delivery_attempts > max_attempts:
                # Poison message: the recipient keeps accepting the connection
                # but never acks. Dead-letter instead of looping for ever.
                await self._repo.move_to_dead_letter(
                    relay_id=msg.relay_id,
                    sender_id=msg.sender_id,
                    recipient_id=msg.recipient_id,
                    reason="max_attempts_exceeded",
                    envelope=msg.envelope_json,
                    detail=f"{msg.delivery_attempts} delivery attempts",
                    delivery_attempts=msg.delivery_attempts,
                )
                await self._repo.log_delivery(
                    relay_id=msg.relay_id,
                    sender_id=msg.sender_id,
                    recipient_id=msg.recipient_id,
                    status="dead_lettered",
                )
                logger.error(
                    "Dead-lettered %s after %d attempts to %s",
                    msg.relay_id,
                    msg.delivery_attempts,
                    agent_id,
                )
                continue

            delivery = Delivery(relay_id=msg.relay_id, envelope=msg.envelope_json)
            success = await self._cm.send_to(agent_id, delivery.model_dump())
            if success:
                sent_count += 1
                await self._repo.log_delivery(
                    relay_id=msg.relay_id,
                    sender_id=msg.sender_id,
                    recipient_id=msg.recipient_id,
                    status="sent",
                )
                logger.debug(
                    "Sent queued message %s to %s (awaiting ack)",
                    msg.relay_id,
                    agent_id,
                )
            else:
                # Send failed: release the lease so another attempt (possibly
                # on another replica) can retry it.
                await self._repo.release_lease(msg.relay_id, reason="send_failed")
                logger.warning(
                    "Failed to send queued message %s to %s - released lease",
                    msg.relay_id,
                    agent_id,
                )
                break  # preserve per-recipient ordering

        if sent_count > 0:
            logger.info(
                "Sent %d queued message(s) to %s (awaiting acks)",
                sent_count,
                agent_id,
            )
        return sent_count

    async def acknowledge(self, relay_id: str) -> bool:
        """Record a recipient's ack. This is what marks a message delivered."""
        return await self._repo.acknowledge_delivery(relay_id)

    async def redeliver_pending(self, *, limit_recipients: int = 500) -> int:
        """Sweep: flush pending messages for every LOCALLY connected agent.

        This is what makes cross-replica delivery work: a message queued while
        the recipient was attached to another replica is picked up once its
        connection lands here. Only local connections are considered, so no
        row can be claimed by two replicas at once.
        """
        recipients = await self._repo.list_recipients_with_pending(
            limit=limit_recipients
        )
        total = 0
        for recipient_id in recipients:
            if not self._cm.is_online(recipient_id):
                continue
            total += await self.flush_to_agent(recipient_id)
        return total

    async def cleanup_expired(self) -> int:
        """Dead-letter expired-undelivered messages, then drop the rest."""
        reaped = await self._repo.reap_expired_to_dead_letter()
        remaining = await self._repo.cleanup_expired()
        if remaining > 0:
            logger.info(
                "Cleaned up %d expired queued message(s) (%d already dead-lettered)",
                remaining,
                reaped,
            )
        return reaped + remaining


__all__ = ["OfflineQueue"]
