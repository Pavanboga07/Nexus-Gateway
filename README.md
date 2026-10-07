# Nexus Gateway — Independent Agent Relay Service

The **Nexus Gateway** is a standalone, hostable WebSocket relay service designed to route cryptographically signed Agent-to-Agent (A2A) messages between Nexus instances across NAT, firewalls, and dynamic IP environments.

---

## 1. Architectural Thesis

In default peer-to-peer setups, two personal agents communicating over HTTP require public IP addresses or port forwarding. For agents running on laptops, home servers, or mobile devices behind NAT, direct HTTP POST inbound delivery is impossible without a relay.

The Nexus Gateway solves this by maintaining long-lived outbound WebSocket connections:

```
┌─────────────────────────────────────────────────────────────┐
│                      NEXUS GATEWAY                          │
│                   (:9000 WebSocket / REST)                  │
│                                                             │
│  ┌───────────────────────┐       ┌───────────────────────┐  │
│  │   ConnectionManager   │       │     Offline Queue     │  │
│  │  (agent_id -> socket) │       │  (PostgreSQL storage) │  │
│  └───────────┬───────────┘       └───────────┬───────────┘  │
└──────────────┼───────────────────────────────┼──────────────┘
               │ Outbound WebSocket            │ Outbound WebSocket
               │ (WSS)                         │ (WSS)
        ┌──────┴──────┐                 ┌──────┴──────┐
        │   Nexus A   │                 │   Nexus B   │
        │ behind NAT  │                 │ behind NAT  │
        └─────────────┘                 └─────────────┘
```

### Complete Service Independence
- **Zero Nexus Code Imports**: The gateway imports nothing from the Nexus application. The Ed25519 primitives it needs are vendored in `relay/crypto.py` and the invite-code validator in `relay/pairing.py` — no shared packages, no monorepo coupling.
- **Dedicated Database**: Connects to its own database (`RELAY_DATABASE_URL`), completely isolated from any Nexus instance's database.
- **Own Configuration**: Configured exclusively via `RELAY_*` environment variables (plus `PORT`).
- **Independently Hostable**: Can be packaged, containerized, and deployed on any cloud VM or container service without Nexus.

---

## 2. Security Boundaries & Threat Model

The gateway operates under a **zero-trust / potentially compromised relay** model:

1. **No Private Key Knowledge**:
   The gateway never receives, generates, or stores private keys. All signing occurs locally on Nexus instances.
2. **Challenge-Response Authentication**:
   When an agent connects to `WS /ws`, the gateway issues a random cryptographic challenge (`os.urandom(32)`). The agent signs this challenge using its Ed25519 identity key. The gateway verifies that:
   - `agent_id == nexus:ed25519:<SHA-256(public_key)[:16 hex]>`
   - The signature over the challenge bytes verifies against `public_key`.
3. **End-to-End Envelope Integrity**:
   The A2A payload and metadata are signed end-to-end between the sending and receiving agents. If a malicious or compromised gateway alters any byte of the forwarded envelope, signature verification on the receiving agent immediately rejects it.
4. **Sender Identity Spoofing Protection**:
   The gateway validates that `envelope.sender` matches the authenticated agent ID of the active WebSocket connection. Agents cannot impersonate other senders.
5. **No Policy or Memory Authority**:
   The gateway has no access to personal memories, user prompts, API keys, or policy rules. Authorization remains strictly authoritative on each local Nexus instance.

---

## 3. Wire Protocol Specification

All frames exchanged over `WS /ws` are JSON documents with a discriminator field `"type"`. Every server-initiated frame carries a `correlation_id` so clients can correlate responses.

### 3.1 Authentication Handshake

```
Agent (Client)                                   Gateway (Server)
      │                                                 │
      ├────────────── Connect to /ws ──────────────────►│
      │                                                 │
      │◄───────────── auth_challenge ───────────────────┤
      │   {                                             │
      │     "type": "auth_challenge",                   │
      │     "challenge": "<base64 random 32 bytes>",    │
      │     "correlation_id": "corr_..."                │
      │   }                                             │
      │                                                 │
      ├────────────── auth_response ───────────────────►│
      │   {                                             │
      │     "type": "auth_response",                    │
      │     "agent_id": "nexus:ed25519:<32 hex>",       │
      │     "public_key": "<base64 raw 32 bytes>",      │
      │     "signature": "<base64 64-byte signature>",  │
      │     "display_name": "My Agent"  // optional     │
      │   }                                             │
      │                                                 │
      │◄───────────── auth_result ──────────────────────┤
      │   {                                             │
      │     "type": "auth_result",                      │
      │     "success": true,                            │
      │     "agent_id": "nexus:ed25519:<32 hex>",       │
      │     "correlation_id": "corr_..."                │
      │   }                                             │
```

Rules:
- The challenge is single-use and expires after 120s; the response must arrive within `RELAY_AUTH_TIMEOUT_SECONDS` (default 10s) or the socket is closed with code 4401 (slowloris guard).
- `agent_id` must equal `nexus:ed25519:` + first 32 hex chars of `SHA-256(public_key)`; the signature must verify over the raw challenge bytes.
- One session per agent: a new authenticated connection supersedes the old one, which receives `{"type": "error", "code": "SESSION_SUPERSEDED"}` and is closed (4401).
- Failure: `{"type": "auth_result", "success": false, "code": "<INVALID_CHALLENGE|REPLAY|EXPIRED_CHALLENGE|IDENTITY_MISMATCH|INVALID_SIGNATURE>", "message": "...", "correlation_id": "corr_..."}` then close 4401.

### 3.2 Message Relaying

#### Sending (`relay_envelope` from Agent to Gateway)
```json
{
  "type": "relay_envelope",
  "relay_id": "relay_f47ac10b58cc4372a5670e02b2c3d479",
  "recipient": "nexus:ed25519:7e45b412a874f67c3098d752e50529d3",
  "correlation_id": "corr_9d2c...",
  "envelope": {
    "protocol": "nexus-a2a",
    "version": "0.3",
    "message_id": "msg_8b05615d18e84ef1867c9d2f6fa72e50",
    "correlation_id": "corr_9d2c...",
    "sender": "nexus:ed25519:e43a6d7bf392110c765fa8901234abcd",
    "recipient": "nexus:ed25519:7e45b412a874f67c3098d752e50529d3",
    "timestamp": "2026-09-15T10:00:00Z",
    "expires_at": "2026-09-15T10:01:00Z",
    "message_type": "request",
    "payload": { "action": "ping" },
    "signature": "..."
  }
}
```

Envelope rules (v0.3): `protocol` is `"nexus-a2a"`, `version` is `"0.3"`; `correlation_id` is REQUIRED; timestamps are strict UTC `YYYY-MM-DDTHH:MM:SSZ`; floats are rejected anywhere in the payload; `message_type` is one of `request`, `response`, `approval_request`, `approve`, `reject`, `error`. The gateway schema-validates the envelope and checks `envelope.sender` matches the authenticated connection, but **never verifies the envelope signature** — signatures are end-to-end between agents (see §2.3). Extra fields are rejected.

#### Gateway Response to Sender
```json
{
  "type": "delivery_ack",
  "relay_id": "relay_f47ac10b58cc4372a5670e02b2c3d479",
  "status": "delivered",
  "correlation_id": "corr_9d2c..."
}
```
`status` is `"delivered"` (recipient acked within the timeout), `"queued"` (recipient offline or ack timed out — the message stays queued for redelivery). `correlation_id` is always echoed. Note: `"queued"` means *accepted, subject to capacity* — when a recipient's backlog exceeds the per-recipient cap, the oldest messages are evicted to the DLQ (each eviction is logged with its message IDs).

#### Delivery to Recipient (`delivery` from Gateway to Recipient)
```json
{
  "type": "delivery",
  "relay_id": "dlv_3f9a...",
  "envelope": { "...v0.3 envelope..." },
  "correlation_id": "corr_9d2c..."
}
```
The recipient acknowledges with `{"type": "delivery_ack", "relay_id": "dlv_3f9a..."}`. Unacked messages stay `pending` and are redelivered on the next reconnect (at-least-once). If the recipient is offline at send time, the message is queued and flushed on reconnect.

#### Error frames
```json
{ "type": "error", "code": "INVALID_ENVELOPE", "message": "...", "correlation_id": "corr_..." }
```
Codes: `INVALID_ENVELOPE`, `SENDER_MISMATCH`, `UNAUTHENTICATED`, `UNKNOWN_FRAME`, `SESSION_SUPERSEDED`, `INTERNAL` (unexpected server-side failure handling a frame; the socket stays open).

### 3.3 Heartbeat & Presence

- **Heartbeat**: client sends `{"type": "heartbeat"}` → server replies `{"type": "heartbeat_ack"}` and records presence.
- **Presence query (REST)**: `GET /presence/{agent_id}` → `{"agent_id", "replica_id", "display_name", "last_heartbeat", "stale"}` or `404`. `stale` is `true` when the last heartbeat is older than `RELAY_PRESENCE_STALE_SECONDS` (default 120s).

### 3.4 REST Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Liveness probe |
| `GET` | `/readyz` | Readiness probe (DB reachable) |
| `GET` | `/metrics` | Connections, queue depth, deliveries, drops, auth failures, last cleanup stats. Bearer-token gated when `RELAY_METRICS_TOKEN` is set |
| `GET` | `/presence/{agent_id}` | Last heartbeat for an agent |
| `PUT` | `/directory/{agent_id}` | Publish a signed agent card (rate-limited, `{"card": {...}}`) |
| `GET` | `/directory/{agent_id}` | Fetch one card |
| `GET` | `/directory` | Paginated card listing (`?limit=&offset=`) |
| `POST` | `/invites` | Publish an invite (`{"card", "code", "ttl_seconds"}`; TTL clamped to `RELAY_MAX_INVITE_TTL_SECONDS`, minimum 1) |
| `POST` | `/invites/claim` | Claim an invite with a code (`{"code"}`; wrong codes count toward a per-IP cooldown) |
| `GET` | `/dlq` | Inspect the dead-letter queue (`?recipient=`, paginated) |
| `POST` | `/dlq/redrive` | Move DLQ messages back to pending (`{"recipient"}` and/or `{"message_ids"}`; attempts reset) |

---

## 4. Configuration Reference

Every variable the relay reads. Anything not listed here is not read — if you set it, nothing happens.

| Variable | Default | Description |
|---|---|---|
| `RELAY_DATABASE_URL` | *(required)* | Async Postgres URL, e.g. `postgresql+asyncpg://user:pass@host:5432/db`. The relay refuses to boot without it |
| `PORT` | `9000` | HTTP + WebSocket listen port (Render sets this) |
| `RELAY_LOG_LEVEL` | `INFO` | Logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `RELAY_AUTH_TIMEOUT_SECONDS` | `10` | Max seconds to complete the auth handshake before the socket is closed |
| `RELAY_MAX_WS_MESSAGE_BYTES` | `65536` | Max WebSocket message size in bytes |
| `RELAY_MAX_INVITE_TTL_SECONDS` | `86400` | Cap for `POST /invites` `ttl_seconds` (prevents immortal invites) |
| `RELAY_CLEANUP_INTERVAL_SECONDS` | `300` | Retention sweeper interval in seconds (`0` disables) |
| `RELAY_DELIVERED_RETENTION_DAYS` | `7` | Delivered/expired messages older than this are purged |
| `RELAY_PRESENCE_STALE_SECONDS` | `120` | Seconds after the last heartbeat before `GET /presence/{agent_id}` reports the agent as `stale` |
| `RELAY_METRICS_TOKEN` | *(unset)* | Bearer token gating `/metrics`. **Set this** — when unset, `/metrics` is unauthenticated and the relay logs a warning at boot |
| `RELAY_SELF_PING_URL` | *(unset)* | Free-tier keep-alive target, e.g. `https://your-service.onrender.com` |
| `RELAY_SELF_PING_INTERVAL` | `0` | Keep-alive interval in seconds; the loop is OFF unless both this and the URL are set |

---

## 5. Deployment Options

### Running with Docker Compose (Recommended)

```bash
# POSTGRES_PASSWORD is required (no default is committed); a .env file works too.
export POSTGRES_PASSWORD="a-long-dev-only-password"
docker compose up -d
```

This starts:
- PostgreSQL 16 on host port `5434` with isolated database `nexus_gateway`.
- Nexus Gateway service on port `9000`.

### Running Locally with Python

1. Create a Python 3.12+ virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # or .\venv\Scripts\activate on Windows
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Set your environment variables in `.env` (or copy `.env.example`). `RELAY_DATABASE_URL` is required.
4. Start the gateway:
   ```bash
   python run.py
   ```

No migrations to run: on boot the relay creates the schema on a fresh database with `Base.metadata.create_all()` and then **verifies** every expected table exists, crashing loudly if any is missing.

---

## 6. Connecting Nexus Instances (NAT Traversal Guide)

To enable a Nexus instance to communicate via the gateway:

1. In the Nexus instance's `.env`, specify:
   ```env
   NEXUS_GATEWAY_URL=ws://your-gateway-host:9000/ws
   ```
2. On startup, the Nexus instance establishes an outbound WebSocket to the gateway, completes the cryptographic challenge-response handshake, and registers its `agent_id`.
3. Inbound A2A messages forwarded by the gateway are automatically passed to Nexus's local `A2AService.handle_inbound()` where policy enforcement and signature verification execute.
4. Outbound messages addressed to agents registered on the gateway are sent as `relay_envelope` frames. If the recipient is offline, the gateway buffers them and automatically delivers them when the recipient reconnects.
