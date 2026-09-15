"""WebSocket connection lifecycle manager.

Tracks authenticated agent_id → WebSocket mappings and enforces
connection limits. Thread-safe via asyncio locks.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from starlette.websockets import WebSocket, WebSocketState

logger = logging.getLogger(__name__)


@dataclass
class AgentConnection:
    """Metadata for a single authenticated WebSocket connection."""

    agent_id: str
    public_key: str
    display_name: str | None
    websocket: WebSocket
    connected_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    last_heartbeat: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class ConnectionManager:
    """Manages active WebSocket connections indexed by agent_id.

    Thread-safe: all mutations go through an asyncio Lock.
    """

    def __init__(self, *, max_connections: int = 500) -> None:
        self._connections: dict[str, AgentConnection] = {}
        self._lock = asyncio.Lock()
        self._max_connections = max_connections

    # --- Connection lifecycle ---

    async def register(
        self,
        agent_id: str,
        public_key: str,
        display_name: str | None,
        websocket: WebSocket,
    ) -> AgentConnection:
        """Register a newly authenticated connection.

        If the agent already has a connection, the old one is displaced
        (closed) and replaced with the new one.

        Raises ``ConnectionError`` if the connection limit is reached
        and the agent is not already connected (not a reconnect).
        """
        async with self._lock:
            # Displace existing connection for same agent (reconnect)
            existing = self._connections.get(agent_id)
            if existing is not None:
                logger.info(
                    "Displacing existing connection for %s (reconnect)",
                    agent_id,
                )
                await self._close_websocket(existing.websocket)

            # Check capacity (reconnects don't count toward limit)
            if (
                existing is None
                and len(self._connections) >= self._max_connections
            ):
                raise ConnectionError(
                    f"Connection limit ({self._max_connections}) reached."
                )

            conn = AgentConnection(
                agent_id=agent_id,
                public_key=public_key,
                display_name=display_name,
                websocket=websocket,
            )
            self._connections[agent_id] = conn
            logger.info(
                "Registered connection: %s (total: %d)",
                agent_id,
                len(self._connections),
            )
            return conn

    async def unregister(self, agent_id: str) -> None:
        """Remove a connection. Idempotent."""
        async with self._lock:
            conn = self._connections.pop(agent_id, None)
            if conn is not None:
                logger.info(
                    "Unregistered connection: %s (total: %d)",
                    agent_id,
                    len(self._connections),
                )

    # --- Queries ---

    def get(self, agent_id: str) -> AgentConnection | None:
        """Get connection for an agent, or None if not connected."""
        return self._connections.get(agent_id)

    def is_online(self, agent_id: str) -> bool:
        """Check if an agent has an active connection."""
        conn = self._connections.get(agent_id)
        if conn is None:
            return False
        return conn.websocket.client_state == WebSocketState.CONNECTED

    @property
    def active_count(self) -> int:
        """Number of currently registered connections."""
        return len(self._connections)

    def all_agent_ids(self) -> list[str]:
        """Return all currently connected agent IDs."""
        return list(self._connections.keys())

    # --- Sending ---

    async def send_to(self, agent_id: str, data: dict) -> bool:
        """Send a JSON frame to a connected agent.

        Returns True if sent successfully, False if the agent is not
        connected or the send failed.
        """
        conn = self._connections.get(agent_id)
        if conn is None:
            return False
        try:
            if conn.websocket.client_state == WebSocketState.CONNECTED:
                await conn.websocket.send_json(data)
                return True
        except Exception as exc:
            logger.warning(
                "Failed to send to %s: %s", agent_id, exc
            )
        return False

    # --- Heartbeat ---

    async def update_heartbeat(self, agent_id: str) -> None:
        """Update the last heartbeat timestamp for an agent."""
        conn = self._connections.get(agent_id)
        if conn is not None:
            conn.last_heartbeat = datetime.now(timezone.utc)

    async def check_stale_connections(
        self, timeout_seconds: float
    ) -> list[str]:
        """Return agent_ids whose last heartbeat exceeds timeout."""
        now = datetime.now(timezone.utc)
        stale = []
        for agent_id, conn in self._connections.items():
            elapsed = (now - conn.last_heartbeat).total_seconds()
            if elapsed > timeout_seconds:
                stale.append(agent_id)
        return stale

    # --- Cleanup ---

    async def disconnect_all(self) -> None:
        """Close all connections (shutdown)."""
        async with self._lock:
            for agent_id, conn in list(self._connections.items()):
                await self._close_websocket(conn.websocket)
            self._connections.clear()
            logger.info("All connections closed.")

    @staticmethod
    async def _close_websocket(ws: WebSocket) -> None:
        """Best-effort close."""
        try:
            if ws.client_state == WebSocketState.CONNECTED:
                await ws.close(code=1000, reason="Displaced or shutdown")
        except Exception:
            pass


__all__ = ["AgentConnection", "ConnectionManager"]
