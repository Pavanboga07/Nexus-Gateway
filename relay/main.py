"""Relay boot contract: FRESH EMPTY DATABASE ONLY.

This service assumes a fresh empty Postgres database. There is no
old-schema compatibility, no migration, no ALTER TABLE fallback: boot
runs Base.metadata.create_all() then VERIFIES every expected table
exists and crashes loudly naming any missing table. A sabotaged or
partial schema never serves traffic.

Design: v0.3 envelopes, Ed25519 challenge-response (single-use),
ack-driven outbox (TTL + DLQ + redelivery), UNIQUE dedup, hardened
directory (auth writes, atomic rate limit, pagination, atomic handles,
card signature verification), presence, invites, /health + /readyz +
/metrics, JSON logs with correlation IDs, self-ping OFF by default.

This module is wiring only: REST routes live in ``relay.routes``,
the WebSocket handler in ``relay.socket``, delivery/ack tracking in
``relay.delivery``, and retention cleanup in ``relay.cleanup``.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI, WebSocket
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from relay import cleanup
from relay.db import init_and_verify, make_engine, make_session_factory, resolve_database_url
from relay.delivery import DeliveryTracker
from relay.routes import register_routes
from relay.socket import register_socket
from relay.util import log_event, safe_db_host, safe_db_name

logger = logging.getLogger("relay")

ACK_TIMEOUT_DEFAULT = 5.0
AUTH_TIMEOUT_DEFAULT = 10.0
DIRECTORY_RATE_LIMIT_DEFAULT = 60
CLEANUP_INTERVAL_DEFAULT = 300.0
DELIVERED_RETENTION_DAYS_DEFAULT = 7
MAX_INVITE_TTL_DEFAULT = 86400


@dataclass
class RelayConfig:
    """All relay knobs in one place (env plumbing lives in run.py)."""

    directory_rate_limit: int = DIRECTORY_RATE_LIMIT_DEFAULT
    ack_timeout: float = ACK_TIMEOUT_DEFAULT
    auth_timeout: float = AUTH_TIMEOUT_DEFAULT
    replica_id: str = "relay-1"
    self_ping_url: str | None = None
    self_ping_interval: float = 0.0
    metrics_token: str | None = None
    max_invite_ttl_seconds: int = MAX_INVITE_TTL_DEFAULT
    cleanup_interval_seconds: float = CLEANUP_INTERVAL_DEFAULT
    delivered_retention_days: int = DELIVERED_RETENTION_DAYS_DEFAULT


@dataclass
class RelayContext:
    """Shared runtime state, built once in create_relay_app."""

    config: RelayConfig
    engine: AsyncEngine
    session_factory: async_sessionmaker[AsyncSession]
    live_sockets: dict[str, WebSocket] = field(default_factory=dict)
    tracker: DeliveryTracker | None = None
    counters: dict[str, int] = field(default_factory=lambda: {"auth_failures": 0})
    cleanup_stats: dict[str, Any] = field(default_factory=dict)


def create_relay_app(
    *,
    database_url: str | None = None,
    directory_rate_limit: int = DIRECTORY_RATE_LIMIT_DEFAULT,
    ack_timeout: float = ACK_TIMEOUT_DEFAULT,
    auth_timeout: float = AUTH_TIMEOUT_DEFAULT,
    replica_id: str = "relay-1",
    self_ping_url: str | None = None,
    self_ping_interval: float = 0,
    metrics_token: str | None = None,
    max_invite_ttl_seconds: int = MAX_INVITE_TTL_DEFAULT,
    cleanup_interval_seconds: float = CLEANUP_INTERVAL_DEFAULT,
    delivered_retention_days: int = DELIVERED_RETENTION_DAYS_DEFAULT,
) -> FastAPI:
    config = RelayConfig(
        directory_rate_limit=directory_rate_limit,
        ack_timeout=ack_timeout,
        auth_timeout=auth_timeout,
        replica_id=replica_id,
        self_ping_url=self_ping_url,
        self_ping_interval=self_ping_interval,
        metrics_token=metrics_token,
        max_invite_ttl_seconds=max_invite_ttl_seconds,
        cleanup_interval_seconds=cleanup_interval_seconds,
        delivered_retention_days=delivered_retention_days,
    )
    url = resolve_database_url(database_url)
    engine = make_engine(url)
    session_factory = make_session_factory(engine)
    ctx = RelayContext(
        config=config,
        engine=engine,
        session_factory=session_factory,
        tracker=DeliveryTracker(session_factory, ack_timeout=ack_timeout),
    )

    async def self_ping_loop() -> None:
        import httpx

        while True:
            await asyncio.sleep(config.self_ping_interval)
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    await client.get(f"{config.self_ping_url}/health")
            except Exception as exc:
                log_event("self_ping_failed", error=str(exc))

    async def run_cleanup_once() -> None:
        try:
            async with session_factory() as session:
                stats = await cleanup.run_cleanup(
                    session, delivered_retention_days=config.delivered_retention_days
                )
                await session.commit()
            ctx.cleanup_stats.clear()
            ctx.cleanup_stats.update(stats)
            log_event("cleanup_done", **stats)
        except Exception as exc:
            log_event("cleanup_failed", error=str(exc))

    async def cleanup_loop() -> None:
        await run_cleanup_once()  # don't serve a rotting DB for the first interval
        while True:
            await asyncio.sleep(config.cleanup_interval_seconds)
            await run_cleanup_once()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await init_and_verify(engine)
        log_event("relay_db_ready", host=safe_db_host(url), database=safe_db_name(url))
        if not config.metrics_token:
            logger.warning("RELAY_METRICS_TOKEN is unset: /metrics is unauthenticated")
        tasks: list[asyncio.Task] = []
        if config.self_ping_url and config.self_ping_interval > 0:
            tasks.append(asyncio.create_task(self_ping_loop()))
            log_event("self_ping_enabled", url=config.self_ping_url)
        if config.cleanup_interval_seconds > 0:
            tasks.append(asyncio.create_task(cleanup_loop()))
            log_event(
                "cleanup_enabled",
                interval_seconds=config.cleanup_interval_seconds,
                delivered_retention_days=config.delivered_retention_days,
            )
        yield
        for task in tasks:
            task.cancel()
        await engine.dispose()

    app = FastAPI(title="nexus relay", lifespan=lifespan)
    app.state.relay_config = {
        "directory_rate_limit": config.directory_rate_limit,
        "ack_timeout": config.ack_timeout,
        "auth_timeout": config.auth_timeout,
        "replica_id": config.replica_id,
    }
    register_routes(app, ctx)
    register_socket(app, ctx)
    return app


__all__ = ["RelayConfig", "RelayContext", "create_relay_app"]
