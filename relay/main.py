"""Single-process relay: WebSocket delivery + REST directory + presence.

Decentralized trust: the relay is a dumb pipe with smart edges — it
never sees private keys and cannot forge envelopes (signatures are the
edges' business; the relay checks shape and time windows only). All
shared state lives in Postgres from line one (queue, UNIQUE dedup,
presence, challenges) so a second replica can appear without redesign.

Observability: ``/health`` (liveness), ``/readyz`` (DB check),
``/metrics`` (connections, queue depth, deliveries, drops, auth
failures). Logs are JSON with correlation IDs. The free-tier self-ping
loop exists but is OFF unless explicitly enabled.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from relay import auth, directory, invites, presence, queue
from relay.db import (
    check_ready,
    init_schema,
    make_engine,
    make_session_factory,
    resolve_database_url,
)
from relay.envelope import Envelope, EnvelopeError

logger = logging.getLogger("relay")

WS_CLOSE_UNAUTHORIZED = 4401
ACK_TIMEOUT_DEFAULT = 5.0
DIRECTORY_RATE_LIMIT_DEFAULT = 60


def log_event(event: str, correlation_id: str | None = None, **fields) -> None:
    """One JSON log line (correlation IDs join a multi-hop exchange)."""
    logger.info(json.dumps(
        {"event": event, "correlation_id": correlation_id, **fields}
    ))


def _new_correlation_id() -> str:
    return f"corr_{uuid.uuid4().hex}"


def create_relay_app(
    *,
    database_url: str | None = None,
    directory_rate_limit: int = DIRECTORY_RATE_LIMIT_DEFAULT,
    ack_timeout: float = ACK_TIMEOUT_DEFAULT,
    replica_id: str = "relay-1",
    self_ping_url: str | None = None,
    self_ping_interval: float = 0,
) -> FastAPI:
    """Build the relay app. Self-ping stays OFF unless configured."""
    url = resolve_database_url(database_url)
    engine = make_engine(url)
    Session = make_session_factory(engine)

    live_sockets: dict[str, WebSocket] = {}
    pending_acks: dict[str, dict[str, Any]] = {}
    counters = {"deliveries": 0, "auth_failures": 0}

    async def self_ping_loop() -> None:
        import httpx

        while True:
            await asyncio.sleep(self_ping_interval)
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    await client.get(f"{self_ping_url}/health")
            except Exception as exc:  # stopgap loop must never crash
                log_event("self_ping_failed", error=str(exc))

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await init_schema(engine)
        ping_task = None
        if self_ping_url and self_ping_interval > 0:
            ping_task = asyncio.create_task(self_ping_loop())
            log_event("self_ping_enabled", url=self_ping_url)
        yield
        if ping_task is not None:
            ping_task.cancel()
        await engine.dispose()

    app = FastAPI(title="nexus relay")
    app.state.relay_config = {
        "directory_rate_limit": directory_rate_limit,
        "ack_timeout": ack_timeout,
        "replica_id": replica_id,
    }

    # --- observability + REST ------------------------------------------

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz():
        if await check_ready(engine):
            return {"ready": True}
        return JSONResponse(status_code=503, content={"ready": False})

    @app.get("/metrics")
    async def metrics():
        async with Session() as session:
            depth = await queue.queue_depth(session)
            drops = await queue.dlq_depth(session)
        return {
            "connections": len(live_sockets),
            "queue_depth": depth,
            "deliveries": counters["deliveries"],
            "drops": drops,
            "auth_failures": counters["auth_failures"],
        }

    @app.get("/presence/{agent_id}")
    async def get_presence(agent_id: str):
        async with Session() as session:
            row = await presence.get_presence(session, agent_id)
        if row is None:
            return JSONResponse(
                status_code=404, content={"detail": "unknown agent"}
            )
        return row

    @app.put("/directory/{agent_id}")
    async def put_card(agent_id: str, body: dict, request: Request):
        card = body.get("card") if isinstance(body, dict) else None
        try:
            ip = request.client.host if request.client else "unknown"
            async with Session() as session:
                await directory.check_rate_limit(
                    session, ip, limit=directory_rate_limit
                )
                if not isinstance(card, dict) or (
                    card.get("agent_id") != agent_id
                ):
                    raise directory.DirectoryError(
                        400, "PATH_MISMATCH",
                        "card agent_id must match the request path",
                    )
                await directory.store_entry(session, card)
                await session.commit()
        except directory.DirectoryError as exc:
            log_event(
                "directory_write_rejected", code=exc.code, agent_id=agent_id
            )
            return JSONResponse(
                status_code=exc.status,
                content={"detail": str(exc), "code": exc.code},
            )
        log_event("directory_write_stored", agent_id=agent_id)
        return {"agent_id": agent_id}

    @app.get("/directory/{agent_id}")
    async def read_card(agent_id: str):
        async with Session() as session:
            card = await directory.get_entry(session, agent_id)
        if card is None:
            return JSONResponse(
                status_code=404, content={"detail": "unknown agent"}
            )
        return {"agent_id": agent_id, "card": card}

    @app.get("/directory")
    async def list_cards(limit: int = 50, offset: int = 0):
        async with Session() as session:
            total, items = await directory.list_entries(
                session, limit=limit, offset=offset
            )
        return {"total": total, "items": items}

    @app.post("/invites")
    async def create_invite(body: dict):
        card = body.get("card") if isinstance(body, dict) else None
        code = body.get("code") if isinstance(body, dict) else None
        ttl = body.get("ttl_seconds", invites.INVITE_TTL_SECONDS)
        try:
            async with Session() as session:
                expires_at = await invites.create_invite_entry(
                    session, card, code, ttl_seconds=ttl
                )
                await session.commit()
        except invites.InviteClaimError as exc:
            log_event("invite_publish_rejected", code=exc.code)
            return JSONResponse(
                status_code=exc.status,
                content={"detail": str(exc), "code": exc.code},
            )
        log_event("invite_published", agent_id=card.get("agent_id"))
        return {
            "agent_id": card.get("agent_id"),
            "expires_at": expires_at.isoformat(),
        }

    @app.post("/invites/claim")
    async def claim_invite(body: dict, request: Request):
        code = body.get("code") if isinstance(body, dict) else None
        ip = request.client.host if request.client else "unknown"
        try:
            async with Session() as session:
                card = await invites.claim_invite_entry(session, code, ip)
                await session.commit()
        except invites.InviteClaimError as exc:
            log_event("invite_claim_rejected", code=exc.code)
            return JSONResponse(
                status_code=exc.status,
                content={"detail": str(exc), "code": exc.code},
            )
        return {"card": card}

    # --- websocket helpers ----------------------------------------------

    async def settle_ack(delivery_id: str) -> bool:
        """Settle a recipient ack; True when a live sender waits on it."""
        entry = pending_acks.get(delivery_id)
        if entry is None:
            return False
        async with Session() as session:
            if await queue.ack_delivered(session, entry["message_id"]):
                await session.commit()
        counters["deliveries"] += 1
        entry["event"].set()
        return True

    def track_delivery(
        delivery_id: str,
        message_id: str,
        sender_ws: WebSocket | None,
        sender_relay_id: str | None,
    ) -> asyncio.Event:
        event = asyncio.Event()
        pending_acks[delivery_id] = {
            "event": event,
            "message_id": message_id,
            "sender_ws": sender_ws,
            "sender_relay_id": sender_relay_id,
        }
        return event

    async def flush_pending(agent_id: str, ws: WebSocket) -> None:
        """Redeliver unacked rows on (re)connect; acks settle whenever."""
        async with Session() as session:
            rows = await queue.claim_for_recipient(session, agent_id)
            await session.commit()
        for row in rows:
            delivery_id = f"dlv_{uuid.uuid4().hex}"
            track_delivery(delivery_id, row["message_id"], None, None)
            try:
                await ws.send_json(
                    {
                        "type": "delivery",
                        "relay_id": delivery_id,
                        "envelope": row["envelope"],
                    }
                )
            except Exception:
                break

    async def handle_envelope(
        ws: WebSocket, agent_id: str, frame: dict[str, Any]
    ) -> None:
        sender_relay_id = frame.get("relay_id")
        raw_envelope = frame.get("envelope")
        recipient = frame.get("recipient")
        correlation_id = (
            frame.get("correlation_id")
            or (raw_envelope.get("correlation_id") if isinstance(raw_envelope, dict) else None)
            or _new_correlation_id()
        )
        try:
            env = Envelope.validate_live(raw_envelope)
        except (ValidationError, EnvelopeError) as exc:
            await ws.send_json(
                {
                    "type": "error",
                    "code": "INVALID_ENVELOPE",
                    "message": f"envelope rejected: {exc}",
                    "correlation_id": correlation_id,
                }
            )
            return
        if not recipient or recipient != env.recipient:
            await ws.send_json(
                {
                    "type": "error",
                    "code": "INVALID_ENVELOPE",
                    "message": "frame recipient must match the envelope",
                    "correlation_id": correlation_id,
                }
            )
            return
        if env.sender != agent_id:
            await ws.send_json(
                {
                    "type": "error",
                    "code": "SENDER_MISMATCH",
                    "message": "envelope sender must match the connection",
                    "correlation_id": correlation_id,
                }
            )
            return
        envelope = env.model_dump(exclude_none=True)
        async with Session() as session:
            try:
                outcome = await queue.enqueue(session, envelope=envelope)
            except ValueError as exc:
                await session.rollback()
                await ws.send_json(
                    {
                        "type": "error",
                        "code": "INVALID_ENVELOPE",
                        "message": str(exc),
                        "correlation_id": correlation_id,
                    }
                )
                return
            await session.commit()
        log_event(
            "envelope_queued", correlation_id,
            message_id=env.message_id, outcome=outcome,
        )
        target = live_sockets.get(env.recipient)
        if target is None:
            await ws.send_json(
                {"type": "delivery_ack",
                 "relay_id": sender_relay_id, "status": "queued"}
            )
            return
        delivery_id = f"dlv_{uuid.uuid4().hex}"
        event = track_delivery(
            delivery_id, env.message_id, ws, sender_relay_id
        )
        try:
            await target.send_json(
                {
                    "type": "delivery",
                    "relay_id": delivery_id,
                    "envelope": envelope,
                    "correlation_id": correlation_id,
                }
            )
        except Exception:
            pending_acks.pop(delivery_id, None)
            await ws.send_json(
                {"type": "delivery_ack",
                 "relay_id": sender_relay_id, "status": "queued"}
            )
            return
        try:
            await asyncio.wait_for(event.wait(), timeout=ack_timeout)
            await ws.send_json(
                {"type": "delivery_ack",
                 "relay_id": sender_relay_id, "status": "delivered"}
            )
        except asyncio.TimeoutError:
            await ws.send_json(
                {"type": "delivery_ack",
                 "relay_id": sender_relay_id, "status": "queued"}
            )
        finally:
            pending_acks.pop(delivery_id, None)

    # --- websocket -------------------------------------------------------

    @app.websocket("/ws")
    async def relay_socket(ws: WebSocket):
        await ws.accept()
        correlation_id = _new_correlation_id()
        agent_id: str | None = None
        try:
            async with Session() as session:
                challenge_b64 = await auth.mint_challenge(session)
                await session.commit()
            await ws.send_json(
                {
                    "type": "auth_challenge",
                    "challenge": challenge_b64,
                    "correlation_id": correlation_id,
                }
            )
            frame = await ws.receive_json()
            if not isinstance(frame, dict) or (
                frame.get("type") != "auth_response"
            ):
                await ws.send_json(
                    {
                        "type": "error",
                        "code": "UNAUTHENTICATED",
                        "message": "first frame must be auth_response",
                        "correlation_id": correlation_id,
                    }
                )
                await ws.close(code=WS_CLOSE_UNAUTHORIZED)
                return
            try:
                async with Session() as session:
                    agent_id = await auth.verify_and_consume(
                        session,
                        challenge_b64=frame.get("challenge", challenge_b64),
                        agent_id=frame.get("agent_id", ""),
                        public_key_b64=frame.get("public_key", ""),
                        signature_b64=frame.get("signature", ""),
                    )
                    await session.commit()
            except auth.AuthError as exc:
                counters["auth_failures"] += 1
                log_event(
                    "auth_failed", correlation_id,
                    code=exc.code,
                    agent_id=frame.get("agent_id"),
                )
                await ws.send_json(
                    {
                        "type": "auth_result",
                        "success": False,
                        "code": exc.code,
                        "message": str(exc),
                        "correlation_id": correlation_id,
                    }
                )
                await ws.close(code=WS_CLOSE_UNAUTHORIZED)
                return
            # Authenticated: no card echo, ever.
            live_sockets[agent_id] = ws
            log_event("auth_ok", correlation_id, agent_id=agent_id)
            await ws.send_json(
                {
                    "type": "auth_result",
                    "success": True,
                    "agent_id": agent_id,
                    "correlation_id": correlation_id,
                }
            )
            async with Session() as session:
                await presence.heartbeat(
                    session, agent_id, replica_id=replica_id
                )
                await session.commit()
            await flush_pending(agent_id, ws)
            while True:
                frame = await ws.receive_json()
                if not isinstance(frame, dict):
                    continue
                kind = frame.get("type")
                if kind == "heartbeat":
                    async with Session() as session:
                        await presence.heartbeat(
                            session, agent_id, replica_id=replica_id
                        )
                        await session.commit()
                    await ws.send_json({"type": "heartbeat_ack"})
                elif kind == "relay_envelope":
                    await handle_envelope(ws, agent_id, frame)
                elif kind == "delivery_ack":
                    await settle_ack(frame.get("relay_id", ""))
                else:
                    await ws.send_json(
                        {
                            "type": "error",
                            "code": "UNKNOWN_FRAME",
                            "message": f"unknown frame type {kind!r}",
                        }
                    )
        except WebSocketDisconnect:
            pass
        finally:
            if agent_id is not None and live_sockets.get(agent_id) is ws:
                del live_sockets[agent_id]
            log_event("socket_closed", correlation_id, agent_id=agent_id)

    return app


__all__ = ["create_relay_app"]
