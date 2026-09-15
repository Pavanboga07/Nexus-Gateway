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
- **Zero Nexus Code Imports**: The gateway contains no imports from `app.memory`, `app.policy`, `app.a2a`, `app.identity`, or any other Nexus modules.
- **Dedicated Database**: Connects to its own database (`GATEWAY_DATABASE_URL`), completely isolated from any Nexus instance's database.
- **Own Configuration**: Configured exclusively via `GATEWAY_*` environment variables.
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

All frames exchanged over `WS /ws` are JSON documents with a discriminator field `"type"`.

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
      │     "protocol": "nexus-gw",                     │
      │     "version": "0.1"                            │
      │   }                                             │
      │                                                 │
      ├────────────── auth_response ───────────────────►│
      │   {                                             │
      │     "type": "auth_response",                    │
      │     "agent_id": "nexus:ed25519:<32 hex>",       │
      │     "public_key": "<base64 raw 32 bytes>",      │
      │     "signature": "<base64 64-byte signature>",  │
      │     "display_name": "My Agent"                  │
      │   }                                             │
      │                                                 │
      │◄───────────── auth_result ──────────────────────┤
      │   {                                             │
      │     "type": "auth_result",                      │
      │     "success": true,                            │
      │     "agent_id": "nexus:ed25519:<32 hex>"        │
      │   }                                             │
```

### 3.2 Message Relaying

#### Sending (`relay_envelope` from Agent to Gateway)
```json
{
  "type": "relay_envelope",
  "relay_id": "relay_f47ac10b58cc4372a5670e02b2c3d479",
  "recipient": "nexus:ed25519:7e45b412a874f67c3098d752e50529d3",
  "envelope": {
    "protocol": "nexus-a2a",
    "version": "0.1",
    "message_id": "msg_8b05615d18e84ef1867c9d2f6fa72e50",
    "task_id": "task_2cf24dba5fb0a30e26e83b2ac5b9e29e",
    "sender": "nexus:ed25519:e43a6d7bf392110c765fa8901234abcd",
    "recipient": "nexus:ed25519:7e45b412a874f67c3098d752e50529d3",
    "timestamp": "2026-09-15T10:00:00Z",
    "expires_at": "2026-09-15T10:01:00Z",
    "message_type": "request",
    "purpose": "availability_inquiry",
    "payload": {
      "action": "disclose_information",
      "data_category": "availability"
    },
    "signature": "..."
  }
}
```

#### Gateway Response to Sender
```json
{
  "type": "delivery_ack",
  "relay_id": "relay_f47ac10b58cc4372a5670e02b2c3d479",
  "status": "delivered" // or "queued", or "duplicate"
}
```

#### Delivery to Recipient (`delivery` from Gateway to Recipient)
```json
{
  "type": "delivery",
  "relay_id": "relay_f47ac10b58cc4372a5670e02b2c3d479",
  "envelope": { ... }
}
```

### 3.3 Heartbeat & Presence

- **Heartbeat**: Ping/Pong frame `{"type": "heartbeat", "timestamp": "2026-09-15T10:00:00Z"}`.
- **Presence Query**: `{"type": "presence_query", "agent_id": "..."}`.
- **Presence Result**: `{"type": "presence_result", "agent_id": "...", "online": true, "last_seen": "..."}`.

---

## 4. Configuration Reference

All settings can be configured via environment variables or a `.env` file:

| Variable | Default | Description |
|---|---|---|
| `GATEWAY_HOST` | `0.0.0.0` | Bind IP address |
| `GATEWAY_PORT` | `9000` | Gateway HTTP and WebSocket port |
| `GATEWAY_DATABASE_URL` | `postgresql+asyncpg://nexus:nexus@localhost:5433/nexus_gateway` | Database connection string |
| `GATEWAY_AUTH_TIMEOUT_SECONDS` | `10.0` | Maximum time allowed to complete auth handshake |
| `GATEWAY_MAX_MESSAGE_SIZE` | `65536` | Maximum message size in bytes (64 KB) |
| `GATEWAY_MESSAGE_TTL_SECONDS` | `86400` | Offline queue message expiration (24h) |
| `GATEWAY_MAX_QUEUE_PER_AGENT` | `1000` | Max queued messages per offline agent |
| `GATEWAY_MAX_CONNECTIONS` | `500` | Maximum concurrent WebSocket connections |
| `GATEWAY_HEARTBEAT_INTERVAL_SECONDS`| `30.0` | Periodic keepalive interval |
| `GATEWAY_QUEUE_CLEANUP_INTERVAL_SECONDS` | `300.0` | Interval for purging expired queue records |
| `GATEWAY_LOG_LEVEL` | `INFO` | Logging verbosity |

---

## 5. Deployment Options

### Running with Docker Compose (Recommended)

```bash
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
3. Set your environment variables in `.env` (or copy `.env.example`).
4. Run migrations:
   ```bash
   alembic upgrade head
   ```
5. Start the gateway:
   ```bash
   python run.py
   ```

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
