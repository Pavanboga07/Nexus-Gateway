"""REST routes for the relay: health, directory, presence, invites, metrics."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from relay import directory, invites, presence, queue
from relay.util import log_event

if TYPE_CHECKING:
    from relay.main import RelayContext


def register_routes(app: FastAPI, ctx: "RelayContext") -> None:
    Session = ctx.session_factory
    config = ctx.config
    live_sockets = ctx.live_sockets
    tracker = ctx.tracker
    counters = ctx.counters
    cleanup_stats = ctx.cleanup_stats

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz():
        from relay.db import check_ready

        if await check_ready(ctx.engine):
            return {"ready": True}
        return JSONResponse(status_code=503, content={"ready": False})

    @app.get("/metrics")
    async def metrics(request: Request):
        if config.metrics_token:
            presented = request.headers.get("authorization", "")
            if presented != f"Bearer {config.metrics_token}":
                return JSONResponse(status_code=401, content={"detail": "metrics token required"})
        async with Session() as session:
            depth = await queue.queue_depth(session)
            drops = await queue.dlq_depth(session)
        payload: dict[str, Any] = {
            "connections": len(live_sockets),
            "queue_depth": depth,
            "deliveries": tracker.delivered_count,
            "drops": drops,
            "auth_failures": counters["auth_failures"],
        }
        if cleanup_stats:
            payload["cleanup"] = dict(cleanup_stats)
        return payload

    @app.get("/presence/{agent_id}")
    async def get_presence(agent_id: str):
        async with Session() as session:
            row = await presence.get_presence(
                session, agent_id, stale_after_seconds=config.presence_stale_seconds
            )
        if row is None:
            return JSONResponse(status_code=404, content={"detail": "unknown agent"})
        return row

    @app.put("/directory/{agent_id}")
    async def put_card(agent_id: str, body: dict, request: Request):
        card = body.get("card") if isinstance(body, dict) else None
        ip = request.client.host if request.client else "unknown"
        # Burn rate-limit budget FIRST, in its own committed transaction, so
        # a failed card validation below cannot roll the hit back: attackers
        # probing with garbage still consume budget.
        try:
            async with Session() as rate_session:
                try:
                    await directory.check_rate_limit(rate_session, ip, limit=config.directory_rate_limit)
                finally:
                    await rate_session.commit()
        except directory.DirectoryError as exc:
            log_event("directory_write_rejected", code=exc.code, agent_id=agent_id)
            return JSONResponse(status_code=exc.status, content={"detail": str(exc), "code": exc.code})
        try:
            if not isinstance(card, dict) or (card.get("agent_id") != agent_id):
                raise directory.DirectoryError(400, "PATH_MISMATCH", "card agent_id must match the request path")
            async with Session() as session:
                await directory.store_entry(session, card)
                await session.commit()
        except directory.DirectoryError as exc:
            log_event("directory_write_rejected", code=exc.code, agent_id=agent_id)
            return JSONResponse(status_code=exc.status, content={"detail": str(exc), "code": exc.code})
        log_event("directory_write_stored", agent_id=agent_id)
        return {"agent_id": agent_id}

    @app.get("/directory/{agent_id}")
    async def read_card(agent_id: str):
        async with Session() as session:
            card = await directory.get_entry(session, agent_id)
        if card is None:
            return JSONResponse(status_code=404, content={"detail": "unknown agent"})
        return {"agent_id": agent_id, "card": card}

    @app.get("/directory")
    async def list_cards(limit: int = 50, offset: int = 0):
        async with Session() as session:
            total, items = await directory.list_entries(session, limit=limit, offset=offset)
        return {"total": total, "items": items}

    @app.get("/dlq")
    async def list_dlq(recipient: str | None = None, limit: int = 50, offset: int = 0):
        async with Session() as session:
            total, items = await queue.list_dlq(session, recipient=recipient, limit=limit, offset=offset)
        return {"total": total, "items": items}

    @app.post("/dlq/redrive")
    async def redrive_dlq(body: dict):
        recipient = body.get("recipient") if isinstance(body, dict) else None
        message_ids = body.get("message_ids") if isinstance(body, dict) else None
        if recipient is None and not message_ids:
            return JSONResponse(
                status_code=400,
                content={"detail": "specify recipient and/or message_ids", "code": "INVALID_REQUEST"},
            )
        if message_ids is not None and not isinstance(message_ids, list):
            return JSONResponse(
                status_code=400,
                content={"detail": "message_ids must be a list", "code": "INVALID_REQUEST"},
            )
        async with Session() as session:
            moved = await queue.redrive_dlq(session, recipient=recipient, message_ids=message_ids)
            await session.commit()
        log_event("dlq_redrive", recipient=recipient, moved=moved)
        return {"redriven": moved}

    @app.post("/invites")
    async def create_invite(body: dict):
        card = body.get("card") if isinstance(body, dict) else None
        code = body.get("code") if isinstance(body, dict) else None
        ttl = body.get("ttl_seconds", invites.INVITE_TTL_SECONDS)
        try:
            ttl_seconds = int(ttl)
        except (TypeError, ValueError):
            ttl_seconds = invites.INVITE_TTL_SECONDS
        if ttl_seconds < 1:
            # A zero/negative TTL is a programming error, not something to
            # silently clamp: the invite would be born expired.
            return JSONResponse(
                status_code=400,
                content={"detail": "ttl_seconds must be >= 1", "code": "INVALID_TTL"},
            )
        # Clamp: a client must not be able to mint effectively immortal invites.
        ttl_seconds = min(ttl_seconds, config.max_invite_ttl_seconds)
        try:
            async with Session() as session:
                expires_at = await invites.create_invite_entry(session, card, code, ttl_seconds=ttl_seconds)
                await session.commit()
        except invites.InviteClaimError as exc:
            log_event("invite_publish_rejected", code=exc.code)
            return JSONResponse(status_code=exc.status, content={"detail": str(exc), "code": exc.code})
        log_event("invite_published", agent_id=card.get("agent_id") if isinstance(card, dict) else None)
        return {
            "agent_id": card.get("agent_id") if isinstance(card, dict) else None,
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
            if exc.code == "INVALID_CODE":
                # Record the failed attempt in its own transaction: the main
                # session is rolled back on this path, which must not eat the
                # hit — otherwise the cooldown never engages.
                async with Session() as attempt_session:
                    left = await invites.record_claim_attempt(attempt_session, ip)
                    await attempt_session.commit()
                detail = f"invite code not recognized ({left} of {invites.MAX_ATTEMPTS} attempts left)."
                log_event("invite_claim_rejected", code=exc.code)
                return JSONResponse(status_code=exc.status, content={"detail": detail, "code": exc.code})
            log_event("invite_claim_rejected", code=exc.code)
            return JSONResponse(status_code=exc.status, content={"detail": str(exc), "code": exc.code})
        return {"card": card}


__all__ = ["register_routes"]
