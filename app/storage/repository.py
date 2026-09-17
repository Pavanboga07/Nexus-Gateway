"""
Database operations for the Nexus Gateway.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, or_, select, text, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .models import (
    DeadLetterMessage,
    DeliveryLog,
    ProcessedRelay,
    QueuedMessage,
    RegisteredAgent,
)

logger = logging.getLogger(__name__)


class HandleConflictError(Exception):
    """Raised when a requested handle is already claimed by another agent."""

    def __init__(self, handle: str) -> None:
        super().__init__(f"Handle '@{handle}' is already claimed.")
        self.handle = handle


class GatewayRepository:
    """Repository for Nexus Gateway database operations."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        """
        Initialize the repository.

        Args:
            session_factory: Async session maker for creating database sessions.
        """
        self._session_factory = session_factory

    async def register_agent(
        self,
        agent_id: str,
        public_key: str,
        display_name: str | None = None,
        handle: str | None = None,
        agent_card: dict[str, Any] | None = None,
    ) -> RegisteredAgent:
        """
        Insert or update an agent record.

        Args:
            agent_id: The unique ID of the agent.
            public_key: The public key of the agent.
            display_name: The display name of the agent.
            handle: Optional unique public handle (e.g. @rahul).
            agent_card: Optional signed public agent card.

        Returns:
            The registered agent record.

        Raises:
            HandleConflictError: the requested handle is already claimed by a
                different agent.

        Handle ownership is enforced atomically inside one transaction: a
        handle is claimed by the first agent that asks for it and can never be
        transferred to a different ``agent_id`` by a later connection.

        Previously the upsert conflicted on ``agent_id`` while ``handle``
        carried a full unique constraint, so a second agent claiming an
        existing handle either knocked the first agent off it or raised an
        opaque IntegrityError.
        """
        clean_handle = handle.lower().lstrip("@") if handle else None
        if not clean_handle and display_name:
            clean_handle = display_name.lower().replace(" ", "")[:32]

        async with self._session_factory() as session:
            if not clean_handle:
                # No handle requested: upsert on agent_id. Many agents may have
                # a NULL handle (the partial index does not cover NULLs).
                stmt = (
                    insert(RegisteredAgent)
                    .values(
                        agent_id=agent_id,
                        public_key=public_key,
                        display_name=display_name,
                        handle=None,
                        agent_card=agent_card,
                        last_seen_at=func.now(),
                    )
                    .on_conflict_do_update(
                        index_elements=["agent_id"],
                        set_={
                            "public_key": text("excluded.public_key"),
                            "display_name": text("excluded.display_name"),
                            "agent_card": text(
                                "COALESCE(excluded.agent_card, "
                                "registered_agents.agent_card)"
                            ),
                            "last_seen_at": text("excluded.last_seen_at"),
                        },
                    )
                    .returning(RegisteredAgent)
                )
                agent = (await session.execute(stmt)).scalar_one()
                await session.commit()
                return agent

            # --- Handle claim -------------------------------------------------
            # The partial unique index (WHERE handle IS NOT NULL) is the ONLY
            # arbiter of handle ownership, and it is the conflict target below.
            #
            # Case A - a row already holds this handle:
            #     DO UPDATE fires only when the incumbent IS us (the WHERE).
            #     A competing claim updates nothing => RETURNING is empty.
            # Case B - no row holds it and this agent_id is new: the row inserts.
            # Case C - no row holds it but this agent_id already exists (it
            #     registered earlier without a handle): the insert collides on
            #     the primary key, handled below.
            #
            # The pre-check with FOR UPDATE serializes competing claims for an
            # existing handle; two brand-new agents racing for a FREE handle
            # are caught by the unique violation in the except branch.
            incumbent = (
                await session.execute(
                    select(RegisteredAgent.agent_id)
                    .where(func.lower(RegisteredAgent.handle) == clean_handle)
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if incumbent is not None and incumbent != agent_id:
                await session.rollback()
                raise HandleConflictError(clean_handle)

            stmt = (
                insert(RegisteredAgent)
                .values(
                    agent_id=agent_id,
                    public_key=public_key,
                    display_name=display_name,
                    handle=clean_handle,
                    agent_card=agent_card,
                    last_seen_at=func.now(),
                )
                .on_conflict_do_update(
                    index_elements=["handle"],
                    index_where=text("handle IS NOT NULL"),
                    set_={
                        "public_key": text("excluded.public_key"),
                        "display_name": text("excluded.display_name"),
                        "last_seen_at": text("excluded.last_seen_at"),
                        "agent_card": text(
                            "COALESCE(excluded.agent_card, "
                            "registered_agents.agent_card)"
                        ),
                    },
                    where=(RegisteredAgent.agent_id == agent_id),
                )
                .returning(RegisteredAgent)
            )
            try:
                agent = (await session.execute(stmt)).scalar_one_or_none()
            except IntegrityError as exc:
                agent = None
                pk_collision = "registered_agents_pkey" in str(exc.orig)
                await session.rollback()
                if pk_collision:
                    # Case C: this agent exists already. Its claim on the free
                    # handle was validated by the pre-check, so attach it.
                    await session.execute(
                        update(RegisteredAgent)
                        .where(RegisteredAgent.agent_id == agent_id)
                        .values(
                            public_key=public_key,
                            display_name=display_name,
                            handle=clean_handle,
                            last_seen_at=func.now(),
                        )
                    )
                    await session.commit()
                    fetched = await session.execute(
                        select(RegisteredAgent).where(
                            RegisteredAgent.agent_id == agent_id
                        )
                    )
                    return fetched.scalar_one()
                # Lost the race for a free handle.
                raise HandleConflictError(clean_handle) from exc

            if agent is None:
                # Case A with a different incumbent (or a lost race).
                await session.rollback()
                raise HandleConflictError(clean_handle)

            await session.commit()
            return agent

    async def search_agents(self, query: str, limit: int = 10) -> list[RegisteredAgent]:
        """Search registered agents by display name, handle, or agent_id."""
        clean_q = query.strip().lower()
        if clean_q.startswith("@"):
            clean_q = clean_q[1:]

        async with self._session_factory() as session:
            stmt = (
                select(RegisteredAgent)
                .where(
                    (func.lower(RegisteredAgent.display_name).contains(clean_q))
                    | (func.lower(RegisteredAgent.handle) == clean_q)
                    | (func.lower(RegisteredAgent.agent_id) == clean_q)
                )
                .limit(limit)
            )
            result = await session.execute(stmt)
            return list(result.scalars().all())

    async def get_agent(self, agent_id: str) -> RegisteredAgent | None:
        """Fetch an agent by agent_id."""
        async with self._session_factory() as session:
            result = await session.execute(
                select(RegisteredAgent).where(RegisteredAgent.agent_id == agent_id)
            )
            return result.scalar_one_or_none()

    async def get_by_handle(self, handle: str) -> RegisteredAgent | None:
        """Fetch an agent by unique handle."""
        clean_handle = handle.strip().lower().lstrip("@")
        async with self._session_factory() as session:
            result = await session.execute(
                select(RegisteredAgent).where(func.lower(RegisteredAgent.handle) == clean_handle)
            )
            return result.scalar_one_or_none()

    async def set_online(self, agent_id: str, online: bool) -> None:
        """
        Update the online status and last_seen_at for an agent.

        Args:
            agent_id: The unique ID of the agent.
            online: The new online status.
        """
        async with self._session_factory() as session:
            agent = await session.get(RegisteredAgent, agent_id)
            if agent:
                agent.is_online = online
                agent.last_seen_at = func.now()
                await session.commit()

    async def list_online_agents(self) -> list[RegisteredAgent]:
        """
        Return all online agents.

        Returns:
            List of online registered agents.
        """
        async with self._session_factory() as session:
            result = await session.execute(
                select(RegisteredAgent).where(RegisteredAgent.is_online == True)
            )
            return list(result.scalars().all())

    async def enqueue_message(
        self, relay_id: str, sender_id: str, recipient_id: str, envelope: dict, expires_at: datetime
    ) -> QueuedMessage:
        """
        Insert a new queued message.

        Args:
            relay_id: The relay ID of the message.
            sender_id: The ID of the sender.
            recipient_id: The ID of the recipient.
            envelope: The opaque signed envelope.
            expires_at: The expiration time of the message.

        Returns:
            The queued message record.
        """
        async with self._session_factory() as session:
            msg = QueuedMessage(
                relay_id=relay_id,
                sender_id=sender_id,
                recipient_id=recipient_id,
                envelope_json=envelope,
                expires_at=expires_at,
            )
            session.add(msg)
            await session.commit()
            await session.refresh(msg)
            return msg

    async def claim_pending_messages(
        self,
        recipient_id: str,
        *,
        limit: int = 100,
        lease_seconds: float = 60.0,
        claimed_by: str | None = None,
        now: datetime | None = None,
    ) -> list[QueuedMessage]:
        """Atomically lease up to ``limit`` pending messages for a recipient.

        Uses ``FOR UPDATE SKIP LOCKED`` so two gateway replicas flushing the
        same recipient cannot both claim the same row. Rows whose lease has
        expired (the claiming replica crashed mid-send) become claimable again,
        which bounds duplicate delivery to the crash window.

        Only rows that have not been acked and have not expired are returned.
        """
        now = now or datetime.now(timezone.utc)
        lease_cutoff = now - timedelta(seconds=lease_seconds)

        async with self._session_factory() as session:
            stmt = (
                select(QueuedMessage)
                .where(
                    QueuedMessage.recipient_id == recipient_id,
                    QueuedMessage.delivered.is_(False),
                    QueuedMessage.expires_at > now,
                    or_(
                        QueuedMessage.in_flight_at.is_(None),
                        QueuedMessage.in_flight_at < lease_cutoff,
                    ),
                )
                .order_by(QueuedMessage.created_at)
                .limit(limit)
                .with_for_update(skip_locked=True)
            )
            rows = list((await session.execute(stmt)).scalars().all())

            for row in rows:
                row.in_flight_at = now
                row.delivery_attempts += 1
                row.claimed_by = claimed_by
            await session.commit()

            # Detach usable values: the session is closed on exit.
            for row in rows:
                session.expunge(row)
            return rows

    async def claim_pending_message_by_id(
        self,
        relay_id: str,
        *,
        lease_seconds: float = 60.0,
        claimed_by: str | None = None,
        now: datetime | None = None,
    ) -> QueuedMessage | None:
        """Lease one specific pending message (router fast path retry)."""
        now = now or datetime.now(timezone.utc)
        lease_cutoff = now - timedelta(seconds=lease_seconds)

        async with self._session_factory() as session:
            stmt = (
                select(QueuedMessage)
                .where(
                    QueuedMessage.relay_id == relay_id,
                    QueuedMessage.delivered.is_(False),
                    QueuedMessage.expires_at > now,
                    or_(
                        QueuedMessage.in_flight_at.is_(None),
                        QueuedMessage.in_flight_at < lease_cutoff,
                    ),
                )
                .with_for_update(skip_locked=True)
            )
            row = (await session.execute(stmt)).scalar_one_or_none()
            if row is None:
                return None
            row.in_flight_at = now
            row.delivery_attempts += 1
            row.claimed_by = claimed_by
            await session.commit()
            session.expunge(row)
            return row

    async def release_lease(self, relay_id: str, *, reason: str) -> None:
        """Return a leased row to the pending pool after a failed send.

        The row stays queued (retryable); ``delivery_attempts`` was already
        incremented by the claim, so the DLQ threshold still advances.
        """
        async with self._session_factory() as session:
            msg = await session.get(QueuedMessage, relay_id)
            if msg is None:
                return
            msg.in_flight_at = None
            msg.claimed_by = None
            await session.commit()
        logger.debug("Released lease on %s (%s)", relay_id, reason)

    async def acknowledge_delivery(self, relay_id: str) -> bool:
        """Mark a message delivered because the recipient ACKED it.

        This is the only path that legitimately sets ``delivered``. Returns
        False when the row is unknown (already reaped) or already delivered -
        both harmless, hence idempotent.
        """
        async with self._session_factory() as session:
            msg = await session.get(QueuedMessage, relay_id)
            if msg is None:
                return False
            if msg.delivered:
                return False
            msg.delivered = True
            msg.acked_at = datetime.now(timezone.utc)
            msg.delivered_at = msg.acked_at
            msg.in_flight_at = None
            await session.commit()
            return True

    async def get_message(self, relay_id: str) -> QueuedMessage | None:
        async with self._session_factory() as session:
            return await session.get(QueuedMessage, relay_id)

    async def list_recipients_with_pending(self, limit: int = 500) -> list[str]:
        """Distinct recipients that have at least one deliverable row.

        Used by the background re-delivery sweep so a message queued while its
        recipient was connected to ANOTHER replica still gets delivered.
        """
        now = datetime.now(timezone.utc)
        async with self._session_factory() as session:
            result = await session.execute(
                select(QueuedMessage.recipient_id)
                .where(
                    QueuedMessage.delivered.is_(False),
                    QueuedMessage.expires_at > now,
                )
                .distinct()
                .limit(limit)
            )
            return [row[0] for row in result.all()]

    async def move_to_dead_letter(
        self,
        *,
        relay_id: str,
        sender_id: str,
        recipient_id: str,
        reason: str,
        envelope: dict | None = None,
        detail: str | None = None,
        delivery_attempts: int = 0,
    ) -> None:
        """Move a poison/undeliverable message to the dead-letter queue.

        The queued row is removed in the same transaction so the message cannot
        be both delivered and dead-lettered.
        """
        async with self._session_factory() as session:
            session.add(
                DeadLetterMessage(
                    relay_id=relay_id,
                    sender_id=sender_id,
                    recipient_id=recipient_id,
                    envelope_json=envelope,
                    reason=reason,
                    detail=detail,
                    delivery_attempts=delivery_attempts,
                )
            )
            await session.execute(
                delete(QueuedMessage).where(QueuedMessage.relay_id == relay_id)
            )
            await session.commit()

    async def list_dead_letters(self, limit: int = 100) -> list[DeadLetterMessage]:
        async with self._session_factory() as session:
            result = await session.execute(
                select(DeadLetterMessage)
                .order_by(DeadLetterMessage.created_at.desc())
                .limit(limit)
            )
            return list(result.scalars().all())

    async def reap_expired_to_dead_letter(self, limit: int = 500) -> int:
        """Dead-letter expired-but-undelivered messages, then drop the rest.

        An expiring message that was never delivered is a real failure, not
        routine cleanup, so it is recorded before deletion instead of vanishing.
        """
        now = datetime.now(timezone.utc)
        async with self._session_factory() as session:
            expired = list(
                (
                    await session.execute(
                        select(QueuedMessage)
                        .where(
                            QueuedMessage.expires_at <= now,
                            QueuedMessage.delivered.is_(False),
                        )
                        .limit(limit)
                        .with_for_update(skip_locked=True)
                    )
                ).scalars().all()
            )
            for msg in expired:
                session.add(
                    DeadLetterMessage(
                        relay_id=msg.relay_id,
                        sender_id=msg.sender_id,
                        recipient_id=msg.recipient_id,
                        envelope_json=msg.envelope_json,
                        reason="expired_undelivered",
                        detail=f"TTL elapsed after {msg.delivery_attempts} attempt(s)",
                        delivery_attempts=msg.delivery_attempts,
                    )
                )
                await session.delete(msg)
            if expired:
                logger.warning(
                    "Dead-lettered %d expired undelivered message(s)", len(expired)
                )
            await session.commit()
            return len(expired)

    async def try_record_relay(
        self, *, relay_id: str, sender_id: str, recipient_id: str
    ) -> bool:
        """Claim a relay_id for processing. False when already processed.

        Replaces the in-process dedup set, so dedup survives restarts and is
        shared across replicas.
        """
        async with self._session_factory() as session:
            result = await session.execute(
                insert(ProcessedRelay)
                .values(
                    relay_id=relay_id,
                    sender_id=sender_id,
                    recipient_id=recipient_id,
                )
                .on_conflict_do_nothing(index_elements=["relay_id"])
                .returning(ProcessedRelay.relay_id)
            )
            inserted = result.scalar_one_or_none() is not None
            await session.commit()
            return inserted

    async def prune_processed_relays(self, *, older_than: datetime) -> int:
        """Bound the dedup table's growth."""
        async with self._session_factory() as session:
            result = await session.execute(
                delete(ProcessedRelay).where(
                    ProcessedRelay.created_at < older_than
                )
            )
            await session.commit()
            return int(result.rowcount or 0)

    async def queue_depth(self) -> int:
        """Number of undelivered, unexpired messages (metric)."""
        now = datetime.now(timezone.utc)
        async with self._session_factory() as session:
            result = await session.execute(
                select(func.count())
                .select_from(QueuedMessage)
                .where(
                    QueuedMessage.delivered.is_(False),
                    QueuedMessage.expires_at > now,
                )
            )
            return int(result.scalar_one())

    async def dead_letter_depth(self) -> int:
        async with self._session_factory() as session:
            result = await session.execute(
                select(func.count()).select_from(DeadLetterMessage)
            )
            return int(result.scalar_one())

    async def list_pending_for_recipient(
        self, recipient_id: str, *, limit: int = 1000
    ) -> list[QueuedMessage]:
        """List pending rows WITHOUT leasing them (queue management only).

        Used for capacity enforcement. It must not lease: leaving a lease on
        rows it keeps would hide them from the delivery path until the lease
        expired.
        """
        now = datetime.now(timezone.utc)
        async with self._session_factory() as session:
            result = await session.execute(
                select(QueuedMessage)
                .where(
                    QueuedMessage.recipient_id == recipient_id,
                    QueuedMessage.delivered.is_(False),
                    QueuedMessage.expires_at > now,
                )
                .order_by(QueuedMessage.created_at)
                .limit(limit)
            )
            rows = list(result.scalars().all())
            for row in rows:
                session.expunge(row)
            return rows

    async def count_queued(self, recipient_id: str) -> int:
        """
        Count undelivered messages for a recipient.

        Args:
            recipient_id: The ID of the recipient.

        Returns:
            Number of queued messages.
        """
        async with self._session_factory() as session:
            result = await session.execute(
                select(func.count())
                .select_from(QueuedMessage)
                .where(
                    QueuedMessage.recipient_id == recipient_id,
                    QueuedMessage.delivered == False,
                )
            )
            return result.scalar_one()

    async def evict_oldest(self, recipient_id: str, keep: int) -> int:
        """
        Delete oldest undelivered messages exceeding the keep limit.

        Args:
            recipient_id: The ID of the recipient.
            keep: Number of newest messages to keep.

        Returns:
            Number of messages deleted.
        """
        async with self._session_factory() as session:
            # Subquery to find messages to delete (those older than the top `keep` messages)
            subquery = (
                select(QueuedMessage.relay_id)
                .where(
                    QueuedMessage.recipient_id == recipient_id,
                    QueuedMessage.delivered == False,
                )
                .order_by(QueuedMessage.created_at.desc())
                .offset(keep)
                .scalar_subquery()
            )

            result = await session.execute(
                delete(QueuedMessage)
                .where(QueuedMessage.relay_id.in_(subquery))
            )
            await session.commit()
            return result.rowcount

    async def cleanup_expired(self) -> int:
        """
        Delete all expired messages.

        Returns:
            Number of messages deleted.
        """
        async with self._session_factory() as session:
            result = await session.execute(
                delete(QueuedMessage).where(QueuedMessage.expires_at < func.now())
            )
            await session.commit()
            return result.rowcount

    async def log_delivery(self, relay_id: str, sender_id: str, recipient_id: str, status: str) -> None:
        """
        Log a delivery attempt.

        Args:
            relay_id: The relay ID of the message.
            sender_id: The ID of the sender.
            recipient_id: The ID of the recipient.
            status: The status of the delivery attempt.
        """
        async with self._session_factory() as session:
            log = DeliveryLog(
                relay_id=relay_id,
                sender_id=sender_id,
                recipient_id=recipient_id,
                status=status,
            )
            session.add(log)
            await session.commit()
