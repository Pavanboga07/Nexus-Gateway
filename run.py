"""Entrypoint for serving the v0.3 relay (ported from nexus-v1).

Builds the app via ``relay.main.create_relay_app``. Configuration is
env-only:

- ``RELAY_DATABASE_URL`` (required): async Postgres URL, e.g.
  ``postgresql+asyncpg://user:pass@host:5432/db``.
- ``PORT`` (optional, default 8000): Render sets this; honored here.
- ``RELAY_SELF_PING_URL`` + ``RELAY_SELF_PING_INTERVAL`` (optional):
  free-tier self-ping loop. OFF unless BOTH are set (interval > 0).
"""

from __future__ import annotations

import os

import uvicorn

from relay.main import create_relay_app

DEFAULT_PORT = 8000


def _self_ping_interval() -> float:
    raw = os.environ.get("RELAY_SELF_PING_INTERVAL", "").strip()
    if not raw:
        return 0
    try:
        return float(raw)
    except ValueError:
        return 0


def main() -> None:
    port = int(os.environ.get("PORT", str(DEFAULT_PORT)))
    app = create_relay_app(
        self_ping_url=os.environ.get("RELAY_SELF_PING_URL") or None,
        self_ping_interval=_self_ping_interval(),
    )
    uvicorn.run(app, host="0.0.0.0", port=port, reload=False)


if __name__ == "__main__":
    main()
