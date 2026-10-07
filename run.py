"""Entrypoint for serving the v0.3 relay.

Builds the app via ``relay.main.create_relay_app``. Configuration is
env-only; every variable is documented in README §4 and .env.example:

- ``RELAY_DATABASE_URL`` (required): async Postgres URL, e.g.
  ``postgresql+asyncpg://user:pass@host:5432/db``.
- ``PORT`` (optional, default 9000): Render sets this; honored here.
- ``RELAY_SELF_PING_URL`` + ``RELAY_SELF_PING_INTERVAL`` (optional):
  free-tier self-ping loop. OFF unless BOTH are set (interval > 0).
"""

from __future__ import annotations

import logging
import os

import uvicorn

from relay.main import (
    AUTH_TIMEOUT_DEFAULT,
    CLEANUP_INTERVAL_DEFAULT,
    DELIVERED_RETENTION_DAYS_DEFAULT,
    MAX_INVITE_TTL_DEFAULT,
    PRESENCE_STALE_SECONDS_DEFAULT,
    create_relay_app,
)

DEFAULT_PORT = 9000
DEFAULT_WS_MAX_MESSAGE_BYTES = 64 * 1024  # 64 KiB per WebSocket frame


def _float(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def configure_logging() -> None:
    level = os.environ.get("RELAY_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )


def main() -> None:
    configure_logging()
    logger = logging.getLogger("relay")
    port = _int("PORT", DEFAULT_PORT)
    app = create_relay_app(
        self_ping_url=os.environ.get("RELAY_SELF_PING_URL") or None,
        self_ping_interval=_float("RELAY_SELF_PING_INTERVAL", 0),
        auth_timeout=_float("RELAY_AUTH_TIMEOUT_SECONDS", AUTH_TIMEOUT_DEFAULT),
        metrics_token=os.environ.get("RELAY_METRICS_TOKEN") or None,
        max_invite_ttl_seconds=_int("RELAY_MAX_INVITE_TTL_SECONDS", MAX_INVITE_TTL_DEFAULT),
        cleanup_interval_seconds=_float("RELAY_CLEANUP_INTERVAL_SECONDS", CLEANUP_INTERVAL_DEFAULT),
        delivered_retention_days=_int("RELAY_DELIVERED_RETENTION_DAYS", DELIVERED_RETENTION_DAYS_DEFAULT),
        presence_stale_seconds=_float("RELAY_PRESENCE_STALE_SECONDS", PRESENCE_STALE_SECONDS_DEFAULT),
    )
    ws_max_size = _int("RELAY_MAX_WS_MESSAGE_BYTES", DEFAULT_WS_MAX_MESSAGE_BYTES)
    logger.info(
        "nexus relay listening on 0.0.0.0:%d (auth_timeout=%.1fs, ws_max_bytes=%d, metrics=%s)",
        port,
        _float("RELAY_AUTH_TIMEOUT_SECONDS", AUTH_TIMEOUT_DEFAULT),
        ws_max_size,
        "token-gated" if os.environ.get("RELAY_METRICS_TOKEN") else "UNAUTHENTICATED",
    )
    uvicorn.run(app, host="0.0.0.0", port=port, reload=False, ws_max_size=ws_max_size)


if __name__ == "__main__":
    main()
