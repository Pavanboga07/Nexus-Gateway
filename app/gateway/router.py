"""Message routing engine.

The router is the core of the gateway: it receives relay_envelope
frames from authenticated agents, validates the sender, and either
delivers the envelope immediately (if the recipient is online) or
queues it for later delivery.

The gateway is a dumb relay — it does NOT verify envelope signatures
(that is the recipient's job). It only validates:

    1. The frame structure is well-formed
    2. The envelope.sender matches the authenticated WebSocket connection
    3. The envelope has the required structure fields
    4. The relay_id is not a duplicate
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from app.gateway.connection import ConnectionManager
from app.gateway.queue import OfflineQueue
from app.schemas.wire import (
    Delivery,
    DeliveryAck,
    DeliveryFailed,
    GatewayError,
    RelayEnvelope,
)
from app.security.validation import (
    validate_envelope_structure,
    validate_relay_sender,
)
from app.storage.repository import GatewayRepository

logger = logging.getLogger(__name__)


class MessageRouter:
    """Routes A2A envelopes between connected agents."""

    def __init__(
        self,
        connection_manager: ConnectionManager,
        queue: OfflineQueue,
        repository: GatewayRepository,
    ) -> None:
        self._cm = connection_manager
        self._queue = queue
        self._repo = repository
        self._seen_relay_ids: set[str] = set()

    async def handle_relay_envelope(
        self,
        frame: RelayEnvelope,
        sender_agent_id: str,
    ) -> dict:
        """Process a relay_envelope frame from an authenticated sender.

        Returns a response frame dict (delivery_ack or delivery_failed).
        """
        relay_id = frame.relay_id
        envelope = frame.envelope

        # --- Deduplication ---
        if relay_id in self._seen_relay_ids:
            return DeliveryAck(
                relay_id=relay_id, status="duplicate"
            ).model_dump()
        self._seen_relay_ids.add(relay_id)

        # Trim dedup set to prevent unbounded growth (keep last 10k)
        if len(self._seen_relay_ids) > 10_000:
            # Convert to list, keep most recent half
            ids = list(self._seen_relay_ids)
            self._seen_relay_ids = set(ids[5_000:])

        # --- Validate envelope structure ---
        valid, error = validate_envelope_structure(envelope)
        if not valid:
            logger.warning(
                "Invalid envelope structure from %s: %s",
                sender_agent_id,
                error,
            )
            return DeliveryFailed(
                relay_id=relay_id,
                reason=f"Invalid envelope structure: {error}",
            ).model_dump()

        # --- Validate sender matches authenticated connection ---
        valid, error = validate_relay_sender(envelope, sender_agent_id)
        if not valid:
            logger.warning(
                "Sender mismatch from %s: %s", sender_agent_id, error
            )
            return DeliveryFailed(
                relay_id=relay_id,
                reason=f"Sender mismatch: {error}",
            ).model_dump()

        recipient_id = envelope.get("recipient", "")

        # --- Route: online delivery or queue ---
        if self._cm.is_online(recipient_id):
            delivery = Delivery(
                relay_id=relay_id,
                envelope=envelope,
            )
            success = await self._cm.send_to(
                recipient_id, delivery.model_dump()
            )
            if success:
                await self._repo.log_delivery(
                    relay_id=relay_id,
                    sender_id=sender_agent_id,
                    recipient_id=recipient_id,
                    status="delivered",
                )
                logger.info(
                    "Delivered %s: %s → %s",
                    relay_id,
                    sender_agent_id,
                    recipient_id,
                )
                return DeliveryAck(
                    relay_id=relay_id, status="delivered"
                ).model_dump()
            else:
                # Send failed — agent might have just disconnected,
                # fall through to queue
                logger.warning(
                    "Online delivery failed for %s, queuing instead",
                    relay_id,
                )

        # --- Queue for offline delivery ---
        await self._queue.enqueue(
            relay_id=relay_id,
            sender_id=sender_agent_id,
            recipient_id=recipient_id,
            envelope=envelope,
        )
        return DeliveryAck(
            relay_id=relay_id, status="queued"
        ).model_dump()


__all__ = ["MessageRouter"]
