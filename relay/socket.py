"""WebSocket endpoint: auth handshake, envelope relay, heartbeats, presence."""

from __future__ import annotations

import asyncio
import uuid
from typing import TYPE_CHECKING, Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from pydantic import ValidationError

from relay import auth, presence, queue
from relay.envelope import Envelope, EnvelopeError
from relay.util import WS_CLOSE_UNAUTHORIZED, log_event, new_correlation_id

if TYPE_CHECKING:
    from relay.main import RelayContext


def register_socket(app: FastAPI, ctx: "RelayContext") -> None:
    Session = ctx.session_factory
    config = ctx.config
    live_sockets = ctx.live_sockets
    tracker = ctx.tracker
    counters = ctx.counters

    async def flush_pending(agent_id: str, ws: WebSocket) -> None:
        """Deliver queued messages after reconnect (fire-and-forget).

        Each delivery is tracked so a later ``delivery_ack`` settles it in
        the DB; anything still in flight when this socket closes is
        dropped by ``drop_recipient`` — no leak, and unacked rows stay
        ``pending`` for the next reconnect.
        """
        async with Session() as session:
            rows = await queue.claim_for_recipient(session, agent_id)
            await session.commit()
        for row in rows:
            delivery_id = f"dlv_{uuid.uuid4().hex}"
            tracker.track(delivery_id, row["message_id"], agent_id)
            try:
                await ws.send_json({"type": "delivery", "relay_id": delivery_id, "envelope": row["envelope"]})
            except Exception:
                tracker.pop(delivery_id)
                break

    async def handle_envelope(ws: WebSocket, agent_id: str, frame: dict[str, Any]) -> None:
        sender_relay_id = frame.get("relay_id")
        raw_envelope = frame.get("envelope")
        recipient = frame.get("recipient")
        correlation_id = (
            frame.get("correlation_id")
            or (raw_envelope.get("correlation_id") if isinstance(raw_envelope, dict) else None)
            or new_correlation_id()
        )
        try:
            env = Envelope.validate_live(raw_envelope)
        except (ValidationError, EnvelopeError) as exc:
            await ws.send_json({"type": "error", "code": "INVALID_ENVELOPE", "message": f"envelope rejected: {exc}", "correlation_id": correlation_id})
            return
        if not recipient or recipient != env.recipient:
            await ws.send_json({"type": "error", "code": "INVALID_ENVELOPE", "message": "frame recipient must match the envelope", "correlation_id": correlation_id})
            return
        if env.sender != agent_id:
            await ws.send_json({"type": "error", "code": "SENDER_MISMATCH", "message": "envelope sender must match the connection", "correlation_id": correlation_id})
            return
        envelope = env.model_dump(exclude_none=True)
        async with Session() as session:
            try:
                outcome = await queue.enqueue(session, envelope=envelope)
            except ValueError as exc:
                await session.rollback()
                await ws.send_json({"type": "error", "code": "INVALID_ENVELOPE", "message": str(exc), "correlation_id": correlation_id})
                return
            await session.commit()
        log_event("envelope_queued", correlation_id, message_id=env.message_id, outcome=outcome)
        target = live_sockets.get(env.recipient)
        if target is None:
            await ws.send_json({"type": "delivery_ack", "relay_id": sender_relay_id, "status": "queued", "correlation_id": correlation_id})
            return
        status = await tracker.deliver_with_ack(
            target,
            envelope,
            message_id=env.message_id,
            recipient=env.recipient,
            correlation_id=correlation_id,
        )
        await ws.send_json({"type": "delivery_ack", "relay_id": sender_relay_id, "status": status, "correlation_id": correlation_id})

    @app.websocket("/ws")
    async def relay_socket(ws: WebSocket):
        await ws.accept()
        correlation_id = new_correlation_id()
        agent_id: str | None = None
        try:
            async with Session() as session:
                challenge_b64 = await auth.mint_challenge(session)
                await session.commit()
            await ws.send_json({"type": "auth_challenge", "challenge": challenge_b64, "correlation_id": correlation_id})
            try:
                frame = await asyncio.wait_for(ws.receive_json(), timeout=config.auth_timeout)
            except asyncio.TimeoutError:
                # Slowloris guard: half-open sockets that never answer the
                # challenge are closed instead of lingering forever.
                log_event("auth_timeout", correlation_id)
                await ws.close(code=WS_CLOSE_UNAUTHORIZED)
                return
            if not isinstance(frame, dict) or (frame.get("type") != "auth_response"):
                await ws.send_json({"type": "error", "code": "UNAUTHENTICATED", "message": "first frame must be auth_response", "correlation_id": correlation_id})
                await ws.close(code=WS_CLOSE_UNAUTHORIZED)
                return
            try:
                async with Session() as session:
                    agent_id = await auth.verify_and_consume(session, challenge_b64=frame.get("challenge", challenge_b64), agent_id=frame.get("agent_id", ""), public_key_b64=frame.get("public_key", ""), signature_b64=frame.get("signature", ""))
                    await session.commit()
            except auth.AuthError as exc:
                counters["auth_failures"] += 1
                log_event("auth_failed", correlation_id, code=exc.code, agent_id=frame.get("agent_id"))
                await ws.send_json({"type": "auth_result", "success": False, "code": exc.code, "message": str(exc), "correlation_id": correlation_id})
                await ws.close(code=WS_CLOSE_UNAUTHORIZED)
                return
            # Single session per agent: a newer connection supersedes the old
            # one instead of leaving a ghost socket processing frames as the
            # same identity.
            old = live_sockets.get(agent_id)
            if old is not None and old is not ws:
                try:
                    await old.send_json({"type": "error", "code": "SESSION_SUPERSEDED", "message": "superseded by a newer session", "correlation_id": correlation_id})
                    await old.close(code=WS_CLOSE_UNAUTHORIZED)
                except Exception:
                    pass
            live_sockets[agent_id] = ws
            log_event("auth_ok", correlation_id, agent_id=agent_id)
            await ws.send_json({"type": "auth_result", "success": True, "agent_id": agent_id, "correlation_id": correlation_id})
            display_name = frame.get("display_name")
            if not isinstance(display_name, str) or not display_name:
                display_name = None
            async with Session() as session:
                await presence.heartbeat(session, agent_id, replica_id=config.replica_id, display_name=display_name)
                await session.commit()
            await flush_pending(agent_id, ws)
            while True:
                frame = await ws.receive_json()
                if not isinstance(frame, dict):
                    continue
                kind = frame.get("type")
                if kind == "heartbeat":
                    async with Session() as session:
                        await presence.heartbeat(session, agent_id, replica_id=config.replica_id)
                        await session.commit()
                    await ws.send_json({"type": "heartbeat_ack"})
                elif kind == "relay_envelope":
                    await handle_envelope(ws, agent_id, frame)
                elif kind == "delivery_ack":
                    await tracker.settle(frame.get("relay_id", ""))
                else:
                    await ws.send_json({"type": "error", "code": "UNKNOWN_FRAME", "message": f"unknown frame type {kind!r}", "correlation_id": correlation_id})
        except WebSocketDisconnect:
            pass
        finally:
            if agent_id is not None:
                if live_sockets.get(agent_id) is ws:
                    del live_sockets[agent_id]
                # Drop any flush deliveries never acked: bounded by construction.
                tracker.drop_recipient(agent_id)
            log_event("socket_closed", correlation_id, agent_id=agent_id)


__all__ = ["register_socket"]
