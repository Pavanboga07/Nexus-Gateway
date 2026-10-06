"""Shared relay helpers: structured log events, correlation IDs, close codes."""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

logger = logging.getLogger("relay")

# WebSocket close code for "not (or no longer) authorized on this socket".
WS_CLOSE_UNAUTHORIZED = 4401


def log_event(event: str, correlation_id: str | None = None, **fields: Any) -> None:
    """Emit one structured JSON log line on the relay logger."""
    logger.info(json.dumps({"event": event, "correlation_id": correlation_id, **fields}))


def new_correlation_id() -> str:
    return f"corr_{uuid.uuid4().hex}"


def safe_db_host(url: str) -> str:
    """Host portion of a DB URL for logs (never userinfo)."""
    try:
        return url.split("@", 1)[1].split("/", 1)[0].split("?", 1)[0]
    except Exception:
        return "unparseable"


def safe_db_name(url: str) -> str:
    """Database name portion of a DB URL for logs (never userinfo)."""
    try:
        rest = url.split("@", 1)[1].split("/", 1)[1]
        return rest.split("?", 1)[0] or "unknown"
    except Exception:
        return "unknown"


__all__ = [
    "WS_CLOSE_UNAUTHORIZED",
    "log_event",
    "new_correlation_id",
    "safe_db_host",
    "safe_db_name",
]
