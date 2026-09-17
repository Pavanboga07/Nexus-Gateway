"""Agent presence tracking.

Thin wrapper that combines in-memory ConnectionManager state with
persistent database records for last_seen tracking.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from app.gateway.connection import ConnectionManager
from app.storage.repository import GatewayRepository, HandleConflictError

logger = logging.getLogger(__name__)


class PresenceTracker:
    """Tracks agent online/offline state across connections and restarts."""

    def __init__(
        self,
        connection_manager: ConnectionManager,
        repository: GatewayRepository,
    ) -> None:
        self._cm = connection_manager
        self._repo = repository

    async def agent_came_online(
        self,
        agent_id: str,
        public_key: str,
        display_name: str | None = None,
        handle: str | None = None,
        agent_card: dict[str, Any] | None = None,
    ) -> None:
        """Record that an agent has connected and authenticated.

        Raises:
            HandleConflictError: the requested handle belongs to another agent.
        """
        await self._repo.register_agent(
            agent_id=agent_id,
            public_key=public_key,
            display_name=display_name,
            handle=handle,
            agent_card=agent_card,
        )
        await self._repo.set_online(agent_id, online=True)
        logger.info("Presence: %s is now ONLINE", agent_id)

    async def agent_went_offline(self, agent_id: str) -> None:
        """Record that an agent has disconnected."""
        await self._repo.set_online(agent_id, online=False)
        logger.info("Presence: %s is now OFFLINE", agent_id)

    def is_online(self, agent_id: str) -> bool:
        """Check if an agent is currently connected (in-memory check)."""
        return self._cm.is_online(agent_id)

    async def get_last_seen(self, agent_id: str) -> datetime | None:
        """Get last_seen timestamp from database."""
        agent = await self._repo.get_agent(agent_id)
        if agent is None:
            return None
        return agent.last_seen_at

    async def get_last_seen_iso(self, agent_id: str) -> str | None:
        """Get last_seen as ISO 8601 string, or None."""
        ts = await self.get_last_seen(agent_id)
        if ts is None:
            return None
        return ts.strftime("%Y-%m-%dT%H:%M:%SZ")

    async def mark_all_offline_on_startup(self) -> None:
        """On gateway startup, mark all agents as offline.

        This ensures stale ``is_online=True`` records from a previous
        gateway process don't persist.
        """
        agents = await self._repo.list_online_agents()
        for agent in agents:
            await self._repo.set_online(agent.agent_id, online=False)
        if agents:
            logger.info(
                "Startup cleanup: marked %d stale agents as offline",
                len(agents),
            )


__all__ = ["PresenceTracker"]
