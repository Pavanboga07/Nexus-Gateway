"""
Database operations for the Nexus Gateway.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .models import DeliveryLog, QueuedMessage, RegisteredAgent


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
        self, agent_id: str, public_key: str, display_name: str | None = None
    ) -> RegisteredAgent:
        """
        Insert or update an agent record.

        Args:
            agent_id: The unique ID of the agent.
            public_key: The public key of the agent.
            display_name: The display name of the agent.

        Returns:
            The registered agent record.
        """
        async with self._session_factory() as session:
            stmt = insert(RegisteredAgent).values(
                agent_id=agent_id,
                public_key=public_key,
                display_name=display_name,
                last_seen_at=func.now(),
            )
            stmt = stmt.on_conflict_do_update(
                index_elements=["agent_id"],
                set_={
                    "public_key": stmt.excluded.public_key,
                    "display_name": stmt.excluded.display_name,
                    "last_seen_at": stmt.excluded.last_seen_at,
                },
            ).returning(RegisteredAgent)
            
            result = await session.execute(stmt)
            agent = result.scalar_one()
            await session.commit()
            return agent

    async def get_agent(self, agent_id: str) -> RegisteredAgent | None:
        """
        Fetch an agent by agent_id.

        Args:
            agent_id: The unique ID of the agent.

        Returns:
            The registered agent if found, else None.
        """
        async with self._session_factory() as session:
            result = await session.execute(
                select(RegisteredAgent).where(RegisteredAgent.agent_id == agent_id)
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

    async def get_queued_messages(self, recipient_id: str, limit: int = 100) -> list[QueuedMessage]:
        """
        Get undelivered messages for a recipient.

        Args:
            recipient_id: The ID of the recipient.
            limit: Maximum number of messages to return.

        Returns:
            List of queued messages ordered by creation time.
        """
        async with self._session_factory() as session:
            result = await session.execute(
                select(QueuedMessage)
                .where(
                    QueuedMessage.recipient_id == recipient_id,
                    QueuedMessage.delivered == False,
                )
                .order_by(QueuedMessage.created_at)
                .limit(limit)
            )
            return list(result.scalars().all())

    async def mark_delivered(self, relay_id: str) -> None:
        """
        Mark a message as delivered.

        Args:
            relay_id: The relay ID of the message to mark as delivered.
        """
        async with self._session_factory() as session:
            msg = await session.get(QueuedMessage, relay_id)
            if msg:
                msg.delivered = True
                msg.delivered_at = func.now()
                msg.delivery_attempts += 1
                await session.commit()

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
