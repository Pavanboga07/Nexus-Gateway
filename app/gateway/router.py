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
    """Routes A2A envelopes between connected agents.

    Deduplication is durable and shared (``processed_relays``) rather than an
    in-process set: the old set was empty after every restart and, worse, each
    replica had its own, so the same relay_id was processed once per replica -
    producing duplicate deliveries exactly when scaling out.
    """

    def __init__(
        self,
        connection_manager: ConnectionManager,
        queue: OfflineQueue,
        repository: GatewayRepository,
        *,
        replica_id: str | None = None,
    ) -> None:
        self._cm = connection_manager
        self._queue = queue
        self._repo = repository
        self._replica_id = replica_id or getattr(queue, "replica_id", "gw")

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

        # --- Validate before claiming a relay_id ---
        # (Validating first means a malformed frame does not burn the id, so a
        # corrected retry with the same id still works.)
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

        valid, error = validate_relay_sender(envelope, sender_agent_id)
        if not valid:
            logger.warning("Sender mismatch from %s: %s", sender_agent_id, error)
            return DeliveryFailed(
                relay_id=relay_id,
                reason=f"Sender mismatch: {error}",
            ).model_dump()

        recipient_id = envelope.get("recipient", "")

        # --- Durable, cross-replica deduplication ---
        is_new = await self._repo.try_record_relay(
            relay_id=relay_id,
            sender_id=sender_agent_id,
            recipient_id=recipient_id,
        )
        if not is_new:
            logger.info("Duplicate relay_id %s ignored", relay_id)
            return DeliveryAck(relay_id=relay_id, status="duplicate").model_dump()

        # --- Route: online delivery or queue ---
        if self._cm.is_online(recipient_id):
            delivery = Delivery(relay_id=relay_id, envelope=envelope)
            success = await self._cm.send_to(recipient_id, delivery.model_dump())
            if success:
                # NOTE: this is "sent", not "delivered". The recipient's
                # delivery_ack is what marks the row delivered (see
                # MessageRouter.acknowledge_delivery / OfflineQueue).
                await self._repo.log_delivery(
                    relay_id=relay_id,
                    sender_id=sender_agent_id,
                    recipient_id=recipient_id,
                    status="sent",
                )
                logger.info(
                    "Sent %s: %s -> %s (awaiting ack)",
                    relay_id,
                    sender_agent_id,
                    recipient_id,
                )
                return DeliveryAck(
                    relay_id=relay_id, status="sent"
                ).model_dump()
            logger.warning(
                "Online send failed for %s, queuing instead", relay_id
            )

        # --- Queue for later delivery ---
        await self._queue.enqueue(
            relay_id=relay_id,
            sender_id=sender_agent_id,
            recipient_id=recipient_id,
            envelope=envelope,
        )
        return DeliveryAck(relay_id=relay_id, status="queued").model_dump()

    async def acknowledge_delivery(self, relay_id: str) -> bool:
        """Mark a message delivered because the recipient acked it."""
        return await self._queue.acknowledge(relay_id)


__all__ = ["MessageRouter"]
