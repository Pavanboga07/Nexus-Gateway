"""Nexus Gateway — FastAPI application.

A completely independent WebSocket relay service for routing signed
A2A envelopes between Nexus agents across NAT boundaries.

This service imports ZERO Nexus internals. It has its own database,
its own configuration, and its own dependencies.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import httpx

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.config import get_settings
from app.gateway.auth import (
    AuthenticatedAgent,
    AuthenticationError,
    authenticate_websocket,
    reject_websocket,
)
from app.gateway.connection import ConnectionManager
from app.gateway.presence import PresenceTracker
from app.gateway.queue import OfflineQueue
from app.gateway.router import MessageRouter
from app.schemas.wire import (
    DeliveryAck,
    GatewayError,
    Heartbeat,
    PresenceQuery,
    PresenceResult,
    RelayEnvelope,
)
from app.storage.models import Base
from app.storage.repository import GatewayRepository

logger = logging.getLogger(__name__)

# --- Application state (set during lifespan) ---
_connection_manager: ConnectionManager | None = None
_repository: GatewayRepository | None = None
_router: MessageRouter | None = None
_presence: PresenceTracker | None = None
_queue: OfflineQueue | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: initialize DB, services, cleanup task."""
    global _connection_manager, _repository, _router, _presence, _queue

    settings = get_settings()

    # Configure logging
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
    )
    logger.info("Starting Nexus Gateway on %s:%d", settings.host, settings.port)

    # --- Database ---
    engine = create_async_engine(
        settings.database_url,
        echo=False,
        pool_size=20,
        max_overflow=10,
    )
    session_factory = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )

    # Create tables if they don't exist
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables ensured.")

    # --- Services ---
    _connection_manager = ConnectionManager(
        max_connections=settings.max_connections,
    )
    _repository = GatewayRepository(session_factory=session_factory)
    _queue = OfflineQueue(
        repository=_repository,
        connection_manager=_connection_manager,
    )
    _presence = PresenceTracker(
        connection_manager=_connection_manager,
        repository=_repository,
    )
    _router = MessageRouter(
        connection_manager=_connection_manager,
        queue=_queue,
        repository=_repository,
    )

    # Mark all agents offline on startup (clean stale state)
    await _presence.mark_all_offline_on_startup()

    # --- Background tasks ---
    cleanup_task = asyncio.create_task(
        _periodic_cleanup(settings.queue_cleanup_interval_seconds)
    )

    self_ping_task: asyncio.Task | None = None
    if settings.self_ping_enabled:
        self_ping_task = asyncio.create_task(
            _self_ping_loop(settings.self_ping_interval_seconds)
        )

    logger.info("Nexus Gateway ready.")
    yield

    # --- Shutdown ---
    cleanup_task.cancel()
    if self_ping_task:
        self_ping_task.cancel()
    try:
        await cleanup_task
        if self_ping_task:
            await self_ping_task
    except asyncio.CancelledError:
        pass

    await _connection_manager.disconnect_all()
    await engine.dispose()
    logger.info("Nexus Gateway shut down.")


async def _periodic_cleanup(interval_seconds: float) -> None:
    """Periodically clean up expired queued messages."""
    while True:
        try:
            await asyncio.sleep(interval_seconds)
            if _queue is not None:
                await _queue.cleanup_expired()
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.error("Queue cleanup error: %s", exc)


async def _self_ping_loop(interval_seconds: float) -> None:
    """Periodically ping the gateway's public URL to prevent idle spin-down on Render / free cloud hosts."""
    # Wait 60 seconds after startup before initial ping
    await asyncio.sleep(60.0)
    while True:
        try:
            settings = get_settings()
            # Render automatically sets RENDER_EXTERNAL_URL
            external_url = os.environ.get("RENDER_EXTERNAL_URL") or settings.public_url
            if external_url:
                target_url = f"{external_url.rstrip('/')}/health"
                try:
                    async with httpx.AsyncClient(timeout=15.0) as client:
                        resp = await client.get(target_url)
                        logger.info(
                            "Keep-alive self-ping to %s: HTTP %d (Render idle timer reset)",
                            target_url,
                            resp.status_code,
                        )
                except Exception as req_err:
                    logger.warning("Keep-alive self-ping failed: %s", req_err)
            else:
                logger.debug(
                    "Keep-alive self-ping skipped: RENDER_EXTERNAL_URL or GATEWAY_PUBLIC_URL not configured"
                )
            await asyncio.sleep(interval_seconds)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.error("Error in keep-alive self-ping loop: %s", exc)
            await asyncio.sleep(interval_seconds)


# --- FastAPI app ---

app = FastAPI(
    title="Nexus Gateway",
    description="Independent WebSocket relay for Nexus agent-to-agent communication",
    version="0.1.0",
    lifespan=lifespan,
)


# --- REST endpoints ---


@app.get("/health")
async def health_check() -> dict:
    """Health check for monitoring and load balancers."""
    settings = get_settings()
    return {
        "status": "healthy",
        "service": "nexus-gateway",
        "version": "0.1.0",
        "port": settings.port,
        "connections": _connection_manager.active_count if _connection_manager else 0,
    }


@app.get("/agents")
async def list_agents() -> dict:
    """List agents known to the gateway (public info only)."""
    if _repository is None:
        return {"agents": [], "total": 0}

    online_agents = await _repository.list_online_agents()
    agents = []
    for agent in online_agents:
        agents.append(
            {
                "agent_id": agent.agent_id,
                "display_name": agent.display_name,
                "is_online": agent.is_online,
                "last_seen_at": (
                    agent.last_seen_at.strftime("%Y-%m-%dT%H:%M:%SZ")
                    if agent.last_seen_at
                    else None
                ),
            }
        )
    return {"agents": agents, "total": len(agents)}


# --- WebSocket endpoint ---


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket) -> None:
    """Main WebSocket endpoint for agent connections.

    Flow:
        1. Accept WebSocket connection
        2. Run challenge-response authentication
        3. Register connection and flush offline queue
        4. Enter message loop
    """
    await ws.accept()

    # --- Authentication ---
    try:
        authed = await authenticate_websocket(ws)
    except AuthenticationError as exc:
        logger.warning("Auth failed: %s", exc.reason)
        await reject_websocket(ws, exc.reason)
        try:
            await ws.close(code=4001, reason="Authentication failed")
        except Exception:
            pass
        return

    agent_id = authed.agent_id
    assert _connection_manager is not None
    assert _presence is not None
    assert _router is not None
    assert _queue is not None

    # --- Register connection ---
    try:
        conn = await _connection_manager.register(
            agent_id=agent_id,
            public_key=authed.public_key,
            display_name=authed.display_name,
            websocket=ws,
        )
    except ConnectionError as exc:
        await reject_websocket(ws, str(exc))
        try:
            await ws.close(code=4002, reason="Connection limit reached")
        except Exception:
            pass
        return

    await _presence.agent_came_online(
        agent_id=agent_id,
        public_key=authed.public_key,
        display_name=authed.display_name,
    )

    # --- Flush offline queue ---
    try:
        flushed = await _queue.flush_to_agent(agent_id)
        if flushed > 0:
            logger.info(
                "Flushed %d queued messages to %s on reconnect",
                flushed,
                agent_id,
            )
    except Exception as exc:
        logger.error("Error flushing queue for %s: %s", agent_id, exc)

    # --- Message loop ---
    try:
        await _message_loop(ws, agent_id)
    except WebSocketDisconnect:
        logger.info("Agent %s disconnected.", agent_id)
    except Exception as exc:
        logger.error("Error in message loop for %s: %s", agent_id, exc)
    finally:
        await _connection_manager.unregister(agent_id)
        await _presence.agent_went_offline(agent_id)


async def _message_loop(ws: WebSocket, agent_id: str) -> None:
    """Process incoming frames from an authenticated agent."""
    assert _router is not None
    assert _connection_manager is not None
    assert _presence is not None

    while True:
        try:
            raw = await ws.receive_json()
        except (json.JSONDecodeError, ValueError):
            error = GatewayError(
                code="INVALID_FRAME",
                message="Expected valid JSON frame.",
            )
            await ws.send_json(error.model_dump())
            continue

        if not isinstance(raw, dict):
            error = GatewayError(
                code="INVALID_FRAME",
                message="Expected JSON object.",
            )
            await ws.send_json(error.model_dump())
            continue

        frame_type = raw.get("type")

        if frame_type == "relay_envelope":
            try:
                frame = RelayEnvelope.model_validate(raw)
            except Exception as exc:
                error = GatewayError(
                    code="INVALID_FRAME",
                    message=f"Malformed relay_envelope: {exc}",
                )
                await ws.send_json(error.model_dump())
                continue

            response = await _router.handle_relay_envelope(frame, agent_id)
            await ws.send_json(response)

        elif frame_type == "delivery_ack":
            # Client acknowledged receipt — nothing to do for now
            pass

        elif frame_type == "heartbeat":
            await _connection_manager.update_heartbeat(agent_id)
            pong = Heartbeat(
                timestamp=datetime.now(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )
            )
            await ws.send_json(pong.model_dump())

        elif frame_type == "presence_query":
            try:
                query = PresenceQuery.model_validate(raw)
            except Exception:
                error = GatewayError(
                    code="INVALID_FRAME",
                    message="Malformed presence_query.",
                )
                await ws.send_json(error.model_dump())
                continue

            online = _connection_manager.is_online(query.agent_id)
            last_seen = await _presence.get_last_seen_iso(query.agent_id)
            result = PresenceResult(
                agent_id=query.agent_id,
                online=online,
                last_seen=last_seen,
            )
            await ws.send_json(result.model_dump())

        else:
            error = GatewayError(
                code="UNKNOWN_FRAME_TYPE",
                message=f"Unknown frame type: {frame_type}",
            )
            await ws.send_json(error.model_dump())


__all__ = ["app"]
