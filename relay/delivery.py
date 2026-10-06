"""In-flight delivery tracking.

Both delivery paths — live forwarding (``handle_envelope``) and the
reconnect flush (``flush_pending``) — go through
``DeliveryTracker.deliver_with_ack``: send one delivery frame, wait for
the recipient's ack up to the timeout, and ALWAYS remove the tracking
entry afterwards (ack, send failure, or timeout). The old code inserted
a dict entry + an orphaned ``asyncio.Event`` per flushed message on
every reconnect and never removed them — a slow unbounded memory leak
on exactly the flaky-client path this relay exists to serve. That leak
is gone by construction here.

Entries for flushed messages that are never acked are dropped when the
recipient's socket closes (``drop_recipient``), so nothing here grows
unbounded. The database stays the source of truth: unacked messages
remain ``pending`` and are redelivered on the next reconnect
(at-least-once delivery).
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from relay import queue


class DeliveryTracker:
    """Tracks deliveries awaiting recipient acks. Bounded by construction."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        ack_timeout: float,
    ) -> None:
        self._session_factory = session_factory
        self._ack_timeout = ack_timeout
        self._pending: dict[str, dict[str, Any]] = {}
        self.delivered_count = 0

    def track(self, delivery_id: str, message_id: str, recipient: str) -> asyncio.Event:
        """Register an in-flight delivery; returns the event the waiter blocks on."""
        event = asyncio.Event()
        self._pending[delivery_id] = {
            "event": event,
            "message_id": message_id,
            "recipient": recipient,
        }
        return event

    def pop(self, delivery_id: str) -> dict[str, Any] | None:
        return self._pending.pop(delivery_id, None)

    def drop_recipient(self, recipient: str) -> int:
        """Forget all in-flight deliveries for a recipient (socket closed)."""
        doomed = [did for did, entry in self._pending.items() if entry["recipient"] == recipient]
        for did in doomed:
            self._pending.pop(did, None)
        return len(doomed)

    @property
    def in_flight(self) -> int:
        return len(self._pending)

    async def settle(self, delivery_id: str) -> bool:
        """Recipient acked: mark the message delivered, wake the waiter."""
        entry = self.pop(delivery_id)
        if entry is None:
            return False
        async with self._session_factory() as session:
            if await queue.ack_delivered(session, entry["message_id"]):
                await session.commit()
        self.delivered_count += 1
        entry["event"].set()
        return True

    async def deliver_with_ack(
        self,
        ws: Any,
        envelope: dict[str, Any],
        *,
        message_id: str,
        recipient: str,
        correlation_id: str | None = None,
    ) -> str:
        """Send one delivery frame; wait for the ack; always clean up.

        Returns ``"delivered"`` if the recipient acked within the
        timeout, else ``"queued"`` (the message stays pending for
        redelivery).
        """
        delivery_id = f"dlv_{uuid.uuid4().hex}"
        event = self.track(delivery_id, message_id, recipient)
        frame: dict[str, Any] = {
            "type": "delivery",
            "relay_id": delivery_id,
            "envelope": envelope,
        }
        if correlation_id is not None:
            frame["correlation_id"] = correlation_id
        try:
            await ws.send_json(frame)
        except Exception:
            self.pop(delivery_id)
            return "queued"
        try:
            await asyncio.wait_for(event.wait(), timeout=self._ack_timeout)
            return "delivered"
        except asyncio.TimeoutError:
            return "queued"
        finally:
            self.pop(delivery_id)


__all__ = ["DeliveryTracker"]
