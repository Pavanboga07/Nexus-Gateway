"""WebSocket endpoint: auth handshake, envelope relay, heartbeats, presence."""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from pydantic import ValidationError

from relay import auth, presence, queue
from relay.envelope import Envelope, EnvelopeError
from relay.util import WS_CLOSE_UNAUTHORIZED, log_event, new_correlation_id

if TYPE_CHECKING:
    from relay.main import RelayContext

# Reconnect drain cap: one slow client must not hog the loop forever.
FLUSH_MAX_PER_RECONNECT = 500


def register_socket(app: FastAPI, ctx: "RelayContext") -> None:
    Session = ctx.session_factory
    config = ctx.config
    live_sockets = ctx.live_sockets
    tracker = ctx.tracker
    counters = ctx.counters

    # Per-recipient FIFO locks: held across flush_pending and the
    # live-delivery section of handle_envelope, so a message arriving
    # mid-flush cannot jump ahead of the queued backlog. Entries are
    # dropped once idle (no live socket, empty queue, lock free).
    recipient_locks: dict[str, asyncio.Lock] = {}
    # Per-socket supersede events: when a newer session supersedes an old
    # one, the old socket's event is set so its receive loop stops
    # processing frames as the agent even if the close frame failed.
    supersede_events: dict[str, asyncio.Event] = {}

    def _recipient_lock(agent_id: str) -> asyncio.Lock:
        lock = recipient_locks.get(agent_id)
        if lock is None:
            lock = asyncio.Lock()
            recipient_locks[agent_id] = lock
        return lock

    async def _maybe_drop_recipient_lock(agent_id: str) -> None:
        """Drop an idle recipient's FIFO lock to keep the map bounded.

        Only when nothing can be using it: no live socket, an empty
        queue, and the lock currently free. The locked() check brackets
        the await so the pop itself is race-free (no await between the
        second check and the pop).
        """
        if live_sockets.get(agent_id) is not None:
            return
        lock = recipient_locks.get(agent_id)
        if lock is None or lock.locked():
            return
        async with Session() as session:
            depth = await queue.queue_depth(session, agent_id)
        if depth != 0:
            return
        if lock.locked() or recipient_locks.get(agent_id) is not lock:
            return
        recipient_locks.pop(agent_id, None)

    async def flush_pending(agent_id: str, ws: WebSocket) -> None:
        """Deliver queued messages after reconnect (fire-and-forget).

        Drains the backlog in claim-sized batches, capped per reconnect
        so one slow client can't hog the loop. Each delivery is tracked
        so a later ``delivery_ack`` settles it in the DB; rows that
        expired mid-flush are skipped (the sweeper marks them expired).
        Holds the recipient's FIFO lock so live deliveries can't jump
        the backlog.
        """
        lock = _recipient_lock(agent_id)
        async with lock:
            sent = 0
            while sent < FLUSH_MAX_PER_RECONNECT:
                async with Session() as session:
                    rows = await queue.claim_for_recipient(session, agent_id)
                    await session.commit()
                if not rows:
                    break
                sent += len(rows)
                now = datetime.now(timezone.utc)
                for row in rows:
                    expires_at = row.get("expires_at")
                    if expires_at is not None:
                        if expires_at.tzinfo is None:
                            expires_at = expires_at.replace(tzinfo=timezone.utc)
                        if expires_at <= now:
                            continue  # expired mid-flush; sweeper reaps it
                    delivery_id = f"dlv_{uuid.uuid4().hex}"
                    tracker.track(delivery_id, row["message_id"], agent_id)
                    try:
                        await ws.send_json({"type": "delivery", "relay_id": delivery_id, "envelope": row["envelope"]})
                    except Exception:
                        tracker.pop(delivery_id)
                        await _maybe_drop_recipient_lock(agent_id)
                        return
            await _maybe_drop_recipient_lock(agent_id)

    async def handle_envelope(ws: WebSocket, agent_id: str, frame: dict[str, Any]) -> None:
        sender_relay_id = frame.get("relay_id") or f"rl_{uuid.uuid4().hex}"
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
        if outcome == "dedup_hit":
            # The envelope is already stored: the recipient gets the STORED
            # bytes via the normal pending path, never this re-sent copy.
            await ws.send_json({"type": "delivery_ack", "relay_id": sender_relay_id, "status": "queued", "correlation_id": correlation_id})
            return
        # FIFO: hold the recipient's lock across the live-delivery section
        # so a message arriving mid-flush can't jump the queued backlog.
        lock = _recipient_lock(env.recipient)
        async with lock:
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
        superseded = asyncio.Event()

        async def guarded(coro, *, what: str) -> None:
            """Run one frame's work; on unexpected failure tell the client
            and keep the socket alive instead of dropping the connection."""
            try:
                await coro
            except (WebSocketDisconnect, asyncio.CancelledError):
                raise
            except Exception as exc:
                log_event("frame_internal_error", correlation_id, frame=what, error=str(exc))
                try:
                    await ws.send_json({"type": "error", "code": "INTERNAL", "message": "internal error handling frame", "correlation_id": correlation_id})
                except Exception:
                    pass

        async def do_heartbeat() -> None:
            async with Session() as session:
                await presence.heartbeat(session, agent_id, replica_id=config.replica_id)
                await session.commit()
            await ws.send_json({"type": "heartbeat_ack"})

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
                old_event = supersede_events.get(agent_id)
                try:
                    await old.send_json({"type": "error", "code": "SESSION_SUPERSEDED", "message": "superseded by a newer session", "correlation_id": correlation_id})
                    await old.close(code=WS_CLOSE_UNAUTHORIZED)
                except Exception:
                    pass
                finally:
                    # Even if the close threw, the old socket must stop
                    # processing frames as this agent: its receive loop
                    # breaks on the event.
                    if old_event is not None:
                        old_event.set()
            live_sockets[agent_id] = ws
            supersede_events[agent_id] = superseded
            log_event("auth_ok", correlation_id, agent_id=agent_id)
            await ws.send_json({"type": "auth_result", "success": True, "agent_id": agent_id, "correlation_id": correlation_id})
            display_name = frame.get("display_name")
            if not isinstance(display_name, str) or not display_name:
                display_name = None
            async with Session() as session:
                await presence.heartbeat(session, agent_id, replica_id=config.replica_id, display_name=display_name)
                await session.commit()
            await guarded(flush_pending(agent_id, ws), what="flush_pending")
            while True:
                if superseded.is_set():
                    break
                frame = await ws.receive_json()
                if not isinstance(frame, dict):
                    continue
                kind = frame.get("type")
                if kind == "heartbeat":
                    await guarded(do_heartbeat(), what="heartbeat")
                elif kind == "relay_envelope":
                    await guarded(handle_envelope(ws, agent_id, frame), what="relay_envelope")
                elif kind == "delivery_ack":
                    await guarded(tracker.settle(frame.get("relay_id", "")), what="delivery_ack")
                else:
                    await ws.send_json({"type": "error", "code": "UNKNOWN_FRAME", "message": f"unknown frame type {kind!r}", "correlation_id": correlation_id})
        except WebSocketDisconnect:
            pass
        finally:
            if agent_id is not None:
                if live_sockets.get(agent_id) is ws:
                    del live_sockets[agent_id]
                    # Drop in-flight flush tracking ONLY while this socket is
                    # still the live one: a superseded socket closing late
                    # must not wipe the new socket's tracked deliveries —
                    # that loses acks and causes duplicate redeliveries.
                    tracker.drop_recipient(agent_id)
                if supersede_events.get(agent_id) is superseded:
                    del supersede_events[agent_id]
                await _maybe_drop_recipient_lock(agent_id)
            log_event("socket_closed", correlation_id, agent_id=agent_id)


__all__ = ["register_socket"]
