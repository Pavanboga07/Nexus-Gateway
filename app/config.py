"""Gateway configuration loaded from environment variables.

All settings use the ``GATEWAY_`` prefix to avoid conflicts with Nexus
settings. The gateway is a completely independent service with its own
database, port, and operational parameters.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings


class GatewaySettings(BaseSettings):
    """Gateway-specific configuration."""

    model_config = {
        "env_prefix": "GATEWAY_",
        "case_sensitive": False,
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }

    # --- Networking ---
    host: str = "0.0.0.0"
    port: int = 9000

    # --- Database (completely separate from Nexus) ---
    database_url: str = "postgresql+asyncpg://nexus:nexus@localhost:5433/nexus_gateway"

    # How the schema is prepared at startup:
    #   auto     create tables when the database is empty, then verify (dev)
    #   migrate  run alembic upgrade head (staging/production - recommended)
    #   verify   assert the schema exists, never modify it
    schema_mode: str = "auto"

    # --- Authentication ---
    auth_timeout_seconds: float = 10.0

    # --- Message limits ---
    max_message_size: int = 65536  # 64 KB
    message_ttl_seconds: int = 86400  # 24 hours
    max_queue_per_agent: int = 1000

    # --- Delivery (M2) ---
    # How long a claimed (in-flight) message is leased to one replica before
    # another replica may retry it. This bounds duplicate delivery to the
    # crash window; it must comfortably exceed a send.
    delivery_lease_seconds: float = 60.0
    # After this many send attempts a message is dead-lettered rather than
    # retried for ever (poison-message protection).
    max_delivery_attempts: int = 10
    # How often the re-delivery sweep runs: flushes pending messages for
    # agents connected to THIS replica (needed for cross-replica delivery).
    redelivery_interval_seconds: float = 5.0
    # How long relay-id dedup rows are retained.
    dedup_retention_seconds: int = 86400

    # --- Connection limits ---
    max_connections: int = 500

    # --- Heartbeat ---
    heartbeat_interval_seconds: float = 30.0
    heartbeat_timeout_seconds: float = 90.0

    # --- Cleanup ---
    queue_cleanup_interval_seconds: float = 300.0  # 5 minutes

    # --- Keep-alive self-ping (OPT-IN; see the warning in main._self_ping_loop) ---
    #
    # OFF by default. This is a workaround for one specific hosting behaviour -
    # free tiers that spin an idle container down, which drops every WebSocket -
    # and it is not a property of the gateway. Defaulting it ON made every
    # deployment issue an outbound HTTP request to a URL derived from an
    # environment variable, which is a server-side request forgery primitive
    # armed by default for anyone who can set `GATEWAY_PUBLIC_URL`.
    #
    # It also cannot work everywhere: on a platform that does not define
    # `RENDER_EXTERNAL_URL` the loop does nothing but log, and on a metered
    # deployment it is a request every ten minutes forever.
    self_ping_enabled: bool = False
    self_ping_interval_seconds: float = 600.0  # 10 minutes
    #: The URL to ping. Required when self_ping_enabled is set; validated at
    #: startup (HTTPS, public host) rather than trusted.
    public_url: str | None = None

    # --- Gateway federation (M9) ---
    # Base HTTP URLs of PEER gateways, comma-separated. A gateway can only see
    # the agents connected to IT, so without peers an agent registered on
    # another gateway is simply unknown - there is no global directory.
    #
    # Lookup escalation is deliberately read-only: we ask peers "do you know
    # this agent?" and hand back their answer, but message DELIVERY is not
    # forwarded. A relay must not accept responsibility for a message it cannot
    # confirm it delivered; the sender should be told to retry, and the message
    # should not silently disappear into an unstored hop.
    gateway_peer_urls: str = ""
    # How long a peer lookup may take before it is abandoned.
    gateway_peer_timeout_seconds: float = 5.0
    # Whether peers are consulted at all (off by default: an operator should
    # choose to depend on another deployment's availability).
    gateway_peer_lookup_enabled: bool = False

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
