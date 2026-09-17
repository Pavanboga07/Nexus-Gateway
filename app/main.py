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
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlsplit

import httpx

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, Response
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
from app.gateway.federation import FederatedDirectory
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
from app.storage.repository import GatewayRepository, HandleConflictError
from app.storage.schema import ensure_schema

logger = logging.getLogger(__name__)

# --- Application state (set during lifespan) ---
_federation: FederatedDirectory | None = None
_connection_manager: ConnectionManager | None = None
_repository: GatewayRepository | None = None
_router: MessageRouter | None = None
_presence: PresenceTracker | None = None
_queue: OfflineQueue | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: initialize DB, services, cleanup task."""
    global _connection_manager, _repository, _router, _presence, _queue, _federation

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

    # Schema is owned by migrations (see app/storage/schema.py). This replaces
    # an unconditional create_all() that silently diverged from the migration
    # history and could not express alterations such as the partial unique
    # index that handle arbitration depends on.
    await ensure_schema(
        engine,
        mode=settings.schema_mode,
        database_url=settings.database_url,
    )

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
        replica_id=_queue.replica_id,
    )
    # Federation: peer gateways to consult on a local directory miss (M9).
    # Off unless configured - depending on another deployment's availability
    # should be a deliberate choice.
    _federation = FederatedDirectory()
    if _federation.enabled:
        logger.info("Gateway federation enabled: peers=%s", _federation.peers)
    else:
        logger.info(
            "Gateway federation disabled (set GATEWAY_PEER_LOOKUP_ENABLED=true "
            "and GATEWAY_PEER_URLS to enable cross-gateway discovery)"
        )

    # Mark all agents offline on startup (clean stale state)
    await _presence.mark_all_offline_on_startup()

    # --- Background tasks ---
    cleanup_task = asyncio.create_task(
        _periodic_cleanup(settings.queue_cleanup_interval_seconds)
    )

    # Re-delivery sweep: flushes pending messages for agents connected to THIS
    # replica. Required for correctness with more than one replica, because a
    # message may be queued while the recipient is attached elsewhere - and the
    # connect-time flush only runs on the replica that received the connection.
    redelivery_task = asyncio.create_task(
        _periodic_redelivery(settings.redelivery_interval_seconds)
    )

    self_ping_task: asyncio.Task | None = None
    if settings.self_ping_enabled:
        self_ping_task = asyncio.create_task(
            _self_ping_loop(settings.self_ping_interval_seconds)
        )

    logger.info(
        "Nexus Gateway ready (schema_mode=%s, replica=%s).",
        settings.schema_mode,
        _queue.replica_id if _queue else "n/a",
    )
    yield

    # --- Shutdown ---
    cleanup_task.cancel()
    redelivery_task.cancel()
    if self_ping_task:
        self_ping_task.cancel()
    for task in (cleanup_task, redelivery_task, self_ping_task):
        if task is None:
            continue
        try:
            await task
        except asyncio.CancelledError:
            pass

    await _connection_manager.disconnect_all()
    await engine.dispose()
    logger.info("Nexus Gateway shut down.")


async def _periodic_cleanup(interval_seconds: float) -> None:
    """Periodically dead-letter then drop expired queued messages."""
    while True:
        try:
            await asyncio.sleep(interval_seconds)
            if _queue is not None:
                await _queue.cleanup_expired()
            if _repository is not None:
                cutoff = datetime.now(timezone.utc) - timedelta(
                    seconds=get_settings().dedup_retention_seconds
                )
                pruned = await _repository.prune_processed_relays(older_than=cutoff)
                if pruned:
                    logger.debug("Pruned %d dedup record(s)", pruned)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.error("Queue cleanup error: %s", exc)


async def _periodic_redelivery(interval_seconds: float) -> None:
    """Periodically flush pending messages to locally-connected agents."""
    while True:
        try:
            await asyncio.sleep(interval_seconds)
            if _queue is not None:
                await _queue.redeliver_pending()
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.error("Re-delivery sweep error: %s", exc)


async def _self_ping_loop(interval_seconds: float) -> None:
    """Keep-alive ping to the gateway's own public URL.

    **This is an opt-in workaround, not a feature.** It exists for one hosting
    behaviour: a free tier that spins an idle container down, which silently
    drops every connected agent. `GATEWAY_SELF_PING_ENABLED` is therefore False
    by default (`L2`).

    Two properties matter, and both were wrong before:

    * **The target is validated, not trusted.** The URL comes from
      `RENDER_EXTERNAL_URL` or `GATEWAY_PUBLIC_URL`; pinging it unvalidated turns
      "an operator typo" or "a tampered environment" into a server-side request
      forgery primitive that this process fires every ten minutes. A non-HTTPS
      URL, or one pointing at a loopback/private/link-local address, is refused.
    * **It says so when it cannot work.** Without a URL the loop logs once at
      startup and exits, instead of sleeping forever on a `debug` line nobody
      reads - which is how a keep-alive that was never keeping anything alive
      goes unnoticed.
    """
    target = _resolve_self_ping_target()
    if target is None:
        return

    # Wait 60 seconds after startup before the first ping, so the first request
    # does not race the listener coming up.
    await asyncio.sleep(60.0)
    while True:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(target)
                logger.info(
                    "keep_alive_self_ping url=%s status=%d", target, resp.status_code
                )
        except asyncio.CancelledError:
            break
        except Exception as req_err:  # noqa: BLE001 - a keep-alive must not crash
            logger.warning("keep_alive_self_ping_failed url=%s error=%s", target, req_err)
        try:
            await asyncio.sleep(interval_seconds)
        except asyncio.CancelledError:
            break


#: Hostnames that must never be pinged: this process would be making an
#: outbound request chosen by configuration, so a loopback or private target is
#: refused outright. Not an exhaustive SSRF defence (a public name can resolve
#: to a private address), which is why the endpoint is also required to be HTTPS
#: - but it stops the obvious cases and, more usefully, stops a typo.
_SELF_PING_FORBIDDEN_HOSTS = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "metadata.google.internal",
    "169.254.169.254",
}


def _resolve_self_ping_target() -> str | None:
    """The validated URL to ping, or None (logging why)."""
    settings = get_settings()
    raw = os.environ.get("RENDER_EXTERNAL_URL") or settings.public_url
    if not raw:
        logger.info(
            "keep_alive_self_ping_disabled detail=no RENDER_EXTERNAL_URL or "
            "GATEWAY_PUBLIC_URL configured; the loop will not run"
        )
        return None

    parts = urlsplit(raw)
    if parts.scheme != "https":
        logger.error(
            "keep_alive_self_ping_refused reason=not_https url=%s; the keep-alive "
            "pings a public URL and must not be used to reach anything else",
            raw,
        )
        return None
    host = (parts.hostname or "").lower()
    if not host or host in _SELF_PING_FORBIDDEN_HOSTS or _is_private_host(host):
        logger.error(
            "keep_alive_self_ping_refused reason=non_public_host host=%s", host
        )
        return None
    return f"{raw.rstrip('/')}/health"


def _is_private_host(host: str) -> bool:
    """True for an IP literal in a private, loopback, or link-local range."""
    import ipaddress

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False  # a name, not a literal - see the note above
    return (
        address.is_private or address.is_loopback or address.is_link_local
    )


# --- FastAPI app ---

app = FastAPI(
    title="Nexus Gateway",
    description="Independent WebSocket relay for Nexus agent-to-agent communication",
    version="0.1.0",
    lifespan=lifespan,
)


# --- REST endpoints ---


@app.get("/", response_class=HTMLResponse)
async def root_status() -> str:
    """Landing status page for browsers and monitoring."""
    settings = get_settings()
    count = _connection_manager.active_count if _connection_manager else 0
    ext_url = os.environ.get("RENDER_EXTERNAL_URL") or "http://localhost:9000"
    ws_url = ext_url.replace("https://", "wss://").replace("http://", "ws://") + "/ws"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Nexus Gateway</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #09090b;
            color: #fafafa;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
            padding: 20px;
            box-sizing: border-box;
        }}
        .card {{
            background: #18181b;
            border: 1px solid #27272a;
            border-radius: 12px;
            padding: 32px;
            max-width: 520px;
            width: 100%;
            box-shadow: 0 8px 30px rgba(0,0,0,0.5);
        }}
        .badge {{
            display: inline-flex;
            align-items: center;
            background: rgba(34, 197, 94, 0.15);
            color: #4ade80;
            padding: 4px 12px;
            border-radius: 9999px;
            font-size: 13px;
            font-weight: 600;
            margin-bottom: 16px;
        }}
        .dot {{
            width: 8px;
            height: 8px;
            background: #22c55e;
            border-radius: 50%;
            margin-right: 8px;
        }}
        h1 {{ font-size: 22px; margin: 0 0 8px 0; font-weight: 700; }}
        p {{ color: #a1a1aa; margin: 0 0 20px 0; font-size: 14px; line-height: 1.5; }}
        .label {{ font-size: 12px; color: #71717a; margin-bottom: 6px; font-weight: 500; text-transform: uppercase; letter-spacing: 0.5px; }}
        .endpoint {{
            background: #09090b;
            border: 1px solid #27272a;
            border-radius: 8px;
            padding: 12px 14px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 13px;
            color: #38bdf8;
            word-break: break-all;
            margin-bottom: 20px;
        }}
        .stats {{
            display: flex;
            justify-content: space-between;
            border-top: 1px solid #27272a;
            padding-top: 16px;
            font-size: 13px;
            color: #71717a;
        }}
        .stat-val {{ color: #fafafa; font-weight: 600; }}
    </style>
</head>
<body>
    <div class="card">
        <div class="badge"><span class="dot"></span> Online & Operational</div>
        <h1>Nexus Gateway</h1>
        <p>A standalone WebSocket relay for secure, peer-to-peer Agent-to-Agent (A2A) communication across NAT boundaries.</p>
        
        <div class="label">WebSocket Endpoint</div>
        <div class="endpoint">{ws_url}</div>

        <div class="stats">
            <div>Status: <span class="stat-val">Healthy</span></div>
            <div>Connections: <span class="stat-val">{count}</span></div>
            <div>Version: <span class="stat-val">0.1.0</span></div>
        </div>
    </div>
</body>
</html>"""


@app.get("/favicon.ico", include_in_schema=False)
async def favicon() -> Response:
    return Response(status_code=204)


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


@app.get("/metrics")
async def metrics() -> dict:
    """Operational counters.

    Deliberately small and unauthenticated (like /health) so a scraper or
    uptime check can read it, and deliberately free of agent identities: it
    exposes counts, never who.
    """
    queue_depth = 0
    dead_letter_depth = 0
    if _repository is not None:
        try:
            queue_depth = await _repository.queue_depth()
            dead_letter_depth = await _repository.dead_letter_depth()
        except Exception as exc:  # pragma: no cover - DB hiccup
            logger.warning("metrics_queue_depth_failed: %s", exc)

    return {
        "service": "nexus-gateway",
        "connections": _connection_manager.active_count if _connection_manager else 0,
        "max_connections": get_settings().max_connections,
        "queue_depth": queue_depth,
        "dead_letter_depth": dead_letter_depth,
        "replica_id": _queue.replica_id if _queue else None,
    }


@app.get("/dead-letters")
async def list_dead_letters(limit: int = 50) -> dict:
    """Inspect messages the gateway gave up on (operator diagnostics).

    Returns counts and metadata; the envelope is included because an operator
    diagnosing a stuck integration needs to see what failed (the gateway is a
    relay, and the envelope is already ciphertext-signed and content-agnostic
    to it).
    """
    if _repository is None:
        raise HTTPException(status_code=503, detail="Repository unavailable")
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=400, detail="limit must be 1..500")
    rows = await _repository.list_dead_letters(limit=limit)
    return {
        "dead_letters": [
            {
                "relay_id": r.relay_id,
                "sender_id": r.sender_id,
                "recipient_id": r.recipient_id,
                "reason": r.reason,
                "detail": r.detail,
                "delivery_attempts": r.delivery_attempts,
                "created_at": r.created_at.strftime("%Y-%m-%dT%H:%M:%SZ")
                if r.created_at
                else None,
            }
            for r in rows
        ],
        "total": len(rows),
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
                "handle": f"@{agent.handle}" if getattr(agent, "handle", None) else None,
                "is_online": agent.is_online,
                "last_seen_at": (
                    agent.last_seen_at.strftime("%Y-%m-%dT%H:%M:%SZ")
                    if agent.last_seen_at
                    else None
                ),
            }
        )
    return {"agents": agents, "total": len(agents)}


@app.get("/agents/search")
async def search_agents(q: str = "") -> dict:
    """Public agent directory search (safe public metadata only).
    
    Returns strictly public metadata:
    - agent_id
    - display_name
    - handle (@handle)
    - public_key
    - is_online
    - capabilities
    - last_seen_at

    Does NOT return: memory, email, private contact info, private endpoints, personal data.
    """
    if _repository is None or not q.strip():
        return {"agents": [], "total": 0}

    results = await _repository.search_agents(q.strip(), limit=10)
    agents = []
    for agent in results:
        online = _connection_manager.is_online(agent.agent_id) if _connection_manager else agent.is_online
        agents.append(
            {
                "agent_id": agent.agent_id,
                "display_name": agent.display_name,
                "handle": f"@{agent.handle}" if agent.handle else None,
                "public_key": agent.public_key,
                "is_online": online,
                "capabilities": ["a2a", "scheduling", "task_delegation"],
                "agent_card": agent.agent_card,
                "last_seen_at": (
                    agent.last_seen_at.strftime("%Y-%m-%dT%H:%M:%SZ")
                    if agent.last_seen_at
                    else None
                ),
                "source_gateway": "local",
            }
        )

    # Federation (M9): include peer results so a name search is not silently
    # limited to this gateway. Peer entries carry `source_gateway` so the
    # weaker provenance is visible rather than flattened into the local list.
    if _federation is not None and _federation.enabled:
        known = {a["agent_id"] for a in agents}
        for peer_agent in await _federation.search(q.strip()):
            if peer_agent.get("agent_id") not in known:
                agents.append(peer_agent)

    return {"agents": agents, "total": len(agents)}


@app.get("/agents/handle/{handle}")
async def get_agent_by_handle(handle: str) -> dict:
    """Exact lookup of a registered agent by public handle (e.g. rahul or @rahul).

    On a local miss, peers are consulted (federation, M9): a handle claimed on
    another gateway should not read as "does not exist".
    """
    if _repository is None:
        raise HTTPException(status_code=503, detail="Repository unavailable")
    agent = await _repository.get_by_handle(handle)
    if not agent:
        if _federation is not None:
            peer_answer = await _federation.lookup_handle(handle)
            if peer_answer:
                return {**peer_answer, "source_gateway": "peer"}
        raise HTTPException(status_code=404, detail="Agent handle not found")
    online = _connection_manager.is_online(agent.agent_id) if _connection_manager else False
    return {
        "agent_id": agent.agent_id,
        "display_name": agent.display_name,
        "handle": f"@{agent.handle}" if agent.handle else None,
        "public_key": agent.public_key,
        "is_online": online,
        "agent_card": agent.agent_card,
        "last_seen_at": agent.last_seen_at.strftime("%Y-%m-%dT%H:%M:%SZ") if agent.last_seen_at else None,
        "source_gateway": "local",
    }


@app.get("/agents/{agent_id}")
async def get_agent_by_id(agent_id: str) -> dict:
    """Exact authoritative lookup of an agent by canonical Agent ID.

    On a local miss, peer gateways are consulted (federation, M9). The answer
    is marked with ``source_gateway`` so a caller can tell a local record from
    a peer's claim - a peer's answer is a hint, and the agent's signed card is
    still what establishes identity.
    """
    if _repository is None:
        raise HTTPException(status_code=503, detail="Repository unavailable")
    agent = await _repository.get_agent(agent_id)
    if not agent:
        if _federation is not None:
            peer_answer = await _federation.lookup_agent(agent_id)
            if peer_answer:
                return {**peer_answer, "source_gateway": "peer"}
        raise HTTPException(status_code=404, detail="Agent not found")
    online = _connection_manager.is_online(agent.agent_id) if _connection_manager else False
    return {
        "agent_id": agent.agent_id,
        "display_name": agent.display_name,
        "handle": f"@{agent.handle}" if agent.handle else None,
        "public_key": agent.public_key,
        "is_online": online,
        "agent_card": agent.agent_card,
        "last_seen_at": agent.last_seen_at.strftime("%Y-%m-%dT%H:%M:%SZ") if agent.last_seen_at else None,
        "source_gateway": "local",
    }


@app.get("/agents/{agent_id}/card")
async def get_agent_card(agent_id: str) -> dict:
    """Retrieve the public signed Agent Card for a registered agent."""
    if _repository is None:
        raise HTTPException(status_code=503, detail="Repository unavailable")
    agent = await _repository.get_agent(agent_id)
    if not agent or not agent.agent_card:
        raise HTTPException(status_code=404, detail="Agent card not found")
    return agent.agent_card


@app.get("/agents/{agent_id}/presence")
async def get_agent_presence(agent_id: str) -> dict:
    """Check online/offline presence and last-seen status."""
    if _repository is None:
        raise HTTPException(status_code=503, detail="Repository unavailable")
    online = _connection_manager.is_online(agent_id) if _connection_manager else False
    last_seen = await _presence.get_last_seen_iso(agent_id) if _presence else None
    return {
        "agent_id": agent_id,
        "online": online,
        "last_seen": last_seen,
    }


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

    try:
        await _presence.agent_came_online(
            agent_id=agent_id,
            public_key=authed.public_key,
            display_name=authed.display_name,
            handle=authed.handle,
            agent_card=authed.agent_card,
        )
    except HandleConflictError as exc:
        # A handle is owned by exactly one agent. Refuse the connection rather
        # than letting the newcomer displace the existing owner or crash the
        # socket with an opaque IntegrityError.
        logger.warning(
            "Handle conflict for %s: @%s already claimed", agent_id, exc.handle
        )
        await _connection_manager.unregister(agent_id)
        await reject_websocket(ws, f"Handle '@{exc.handle}' is already claimed.")
        try:
            await ws.close(code=4003, reason="Handle already claimed")
        except Exception:
            pass
        return

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

        if frame_type == "delivery_ack":
            # The recipient's ack is the ONLY evidence of actual delivery.
            # Previously this frame was discarded with a `pass`, so a message
            # was recorded as delivered the moment bytes reached a socket.
            try:
                ack = DeliveryAck.model_validate(raw)
            except Exception:
                await ws.send_json(
                    GatewayError(
                        code="INVALID_FRAME",
                        message="Malformed delivery_ack.",
                    ).model_dump()
                )
                continue

            acked = await _router.acknowledge_delivery(ack.relay_id)
            logger.debug(
                "Ack for %s from %s: %s",
                ack.relay_id,
                agent_id,
                "recorded" if acked else "unknown/already-delivered",
            )

        elif frame_type == "delivery_failed":
            # The recipient could not process a delivery. The row stays
            # pending: its lease expires and the sweep retries it, or it
            # reaches max_delivery_attempts and is dead-lettered. We only log
            # here so a failure cannot silently discard the message.
            relay_id = raw.get("relay_id")
            logger.warning(
                "Recipient %s reported delivery failure for %s: %s",
                agent_id,
                relay_id,
                raw.get("reason", "unspecified"),
            )

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
