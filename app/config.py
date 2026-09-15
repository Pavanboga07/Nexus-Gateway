"""Gateway configuration loaded from environment variables.

All settings use the ``GATEWAY_`` prefix to avoid conflicts with Nexus
settings. The gateway is a completely independent service with its own
database, port, and operational parameters.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings


class GatewaySettings(BaseSettings):
    """Gateway-specific configuration."""

    model_config = {"env_prefix": "GATEWAY_", "case_sensitive": False}

    # --- Networking ---
    host: str = "0.0.0.0"
    port: int = 9000

    # --- Database (completely separate from Nexus) ---
    database_url: str = "postgresql+asyncpg://nexus:nexus@localhost:5433/nexus_gateway"

    # --- Authentication ---
    auth_timeout_seconds: float = 10.0

    # --- Message limits ---
    max_message_size: int = 65536  # 64 KB
    message_ttl_seconds: int = 86400  # 24 hours
    max_queue_per_agent: int = 1000

    # --- Connection limits ---
    max_connections: int = 500

    # --- Heartbeat ---
    heartbeat_interval_seconds: float = 30.0
    heartbeat_timeout_seconds: float = 90.0

    # --- Cleanup ---
    queue_cleanup_interval_seconds: float = 300.0  # 5 minutes

    # --- Logging ---
    log_level: str = "INFO"


_settings: GatewaySettings | None = None


def get_settings() -> GatewaySettings:
    """Return the singleton gateway settings."""
    global _settings
    if _settings is None:
        _settings = GatewaySettings()
    return _settings


__all__ = ["GatewaySettings", "get_settings"]
