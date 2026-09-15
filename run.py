"""Entrypoint for starting the standalone Nexus Gateway service."""

from __future__ import annotations

import os
import uvicorn
from app.config import get_settings


def main() -> None:
    settings = get_settings()
    port = int(os.environ.get("PORT", settings.port))
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=port,
        reload=False,
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    main()
