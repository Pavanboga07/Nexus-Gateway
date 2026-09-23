"""Invite-code pairing (V3).

Flow (approved design): inviter generates a code -> the invite (code
hash -> signed card) is published to the relay -> the claimant fetches
the card with the code -> the claimant verifies the card signature
LOCALLY -> trust screen shows the fingerprint derived from the
VERIFIED card (never relay metadata) -> mutual approve pins keys on
both sides. No QR in v1.

Codes: 6 words from an embedded 2048-entry list (32 x 64 syllable
product, 11 bits/word -> 66 bits) drawn with ``secrets`` (stdlib
only, no new dependency). Single-use, 15-minute expiry. Wrong codes
count attempts: 5 failures -> cooldown. Distinct, safe messages:
wrong -> INVALID_CODE, exhausted -> COOLDOWN, stale -> EXPIRED with a
regenerate hint, replayed -> ALREADY_CLAIMED.

Local SQLite (``store.py`` migration 2): ``invites`` (codes this
device created), ``pair_attempts`` (claimant-side rate limit),
``paired_peers`` (pinned keys). The relay mirrors invites +
attempts in Postgres (see ``relay/invites.py``) and is the arbiter
for consume/expiry; ``unpair`` is local-only and never touches the
network so it works with the peer unreachable.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

CODE_WORDS = 6
INVITE_TTL_SECONDS = 900  # 15 minutes
MAX_CLAIM_ATTEMPTS = 5
COOLDOWN_SECONDS = 300  # 5 minutes
_LOCAL_ATTEMPT_KEY = "claim"

# Embedded wordlist: 32 prefixes x 64 suffixes = 2048 entries.
# Fixed 2-letter prefixes keep every concatenation unique.
_PREFIXES = [
    "al", "ar", "ba", "be", "bi", "bo", "ca", "ce",
    "co", "da", "de", "di", "do", "fa", "fe", "fi",
    "fo", "ga", "ge", "go", "ha", "he", "ka", "ke",
    "la", "le", "ma", "me", "mi", "na", "ne", "pa",
]
_SUFFIXES = [
    "bar", "bay", "bell", "bend", "berry", "birch", "blade", "blaze",
    "brook", "buck", "burrow", "bush", "cedar", "cliff", "cinder", "clover",
    "cove", "crest", "dale", "dell", "drift", "elm", "ember", "fells",
    "fern", "field", "finch", "fjord", "flint", "forest", "fox", "frost",
    "garnet", "glade", "glen", "grove", "harbor", "hawk", "heath", "holly",
    "ivy", "jasper", "juniper", "kelp", "lark", "laurel", "leaf", "linden",
    "loam", "maple", "marsh", "meadow", "mesa", "moss", "oak", "opal",
    "orchard", "otter", "owl", "peak", "pebble", "pine", "plum", "pond",
]
WORDLIST: list[str] = [p + s for p in _PREFIXES for s in _SUFFIXES]
_WORDSET = frozenset(WORDLIST)


class PairingError(ValueError):
    """Pairing failure with machine ``code`` and optional HTTP ``status``."""

    def __init__(self, code: str, message: str, status: int | None = None) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.status = status


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _parse(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def normalize_code(code: Any) -> str:
    """Canonical hyphen form; accepts spaces/case. Raises INVALID_CODE."""
    if not isinstance(code, str):
        raise PairingError("INVALID_CODE", "invite code must be text.")
    parts = [p for p in re.split(r"[\s\-_]+", code.strip().lower()) if p]
    if len(parts) != CODE_WORDS or any(p not in _WORDSET for p in parts):
        raise PairingError(
            "INVALID_CODE", "invite code not recognized; check the words."
        )
    return "-".join(parts)


def generate_code() -> str:
    """Fresh 6-word code (66 bits from ``secrets``)."""
    return "-".join(secrets.choice(WORDLIST) for _ in range(CODE_WORDS))


def code_hash(code: str) -> str:
    """SHA-256 of the normalized code (what is stored / sent as id)."""
    return hashlib.sha256(normalize_code(code).encode("utf-8")).hexdigest()

def _local_attempt_row(conn: sqlite3.Connection) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT failures, cooldown_until FROM pair_attempts WHERE key = ?",
        (_LOCAL_ATTEMPT_KEY,),
    ).fetchone()


def _check_local_cooldown(conn: sqlite3.Connection, now: datetime) -> None:
    row = _local_attempt_row(conn)
    if row is None:
        return
    until = _parse(row["cooldown_until"]) if row["cooldown_until"] else None
    if until is not None and now < until:
        minutes = max(1, int((until - now).total_seconds() // 60))
        raise PairingError(
            "COOLDOWN",
            f"too many wrong codes; try again in about {minutes} minutes.",
            status=429,
        )


def _record_local_failure(conn: sqlite3.Connection, now: datetime) -> None:
    row = _local_attempt_row(conn)
    failures = int(row["failures"]) + 1 if row is not None else 1
    cooldown_until = ""
    if failures >= MAX_CLAIM_ATTEMPTS:
        cooldown_until = _iso(now + timedelta(seconds=COOLDOWN_SECONDS))
    with conn:
        conn.execute(
            "INSERT OR REPLACE INTO pair_attempts "
            "(key, failures, last_failure, cooldown_until) "
            "VALUES (?, ?, ?, ?)",
            (_LOCAL_ATTEMPT_KEY, failures, _iso(now), cooldown_until),
        )


def _clear_local_failures(conn: sqlite3.Connection) -> None:
    with conn:
        conn.execute(
            "DELETE FROM pair_attempts WHERE key = ?", (_LOCAL_ATTEMPT_KEY,)
        )


def create_invite(
    conn: sqlite3.Connection,
    *,
    agent_id: str,
    card: dict[str, Any],
    now: datetime | None = None,
    ttl_seconds: int = INVITE_TTL_SECONDS,
    publish_fn: Callable[[str, dict[str, Any]], Any] | None = None,
) -> dict[str, Any]:
    """Generate a code, publish it, and store it locally. Returns code."""
    at = now or _utcnow()
    code = generate_code()
    if publish_fn is not None:
        publish_fn(code, card)  # raises PairingError; nothing stored then
    expires_at = at + timedelta(seconds=max(0, ttl_seconds))
    with conn:
        conn.execute(
            "INSERT OR REPLACE INTO invites "
            "(code_hash, agent_id, card_json, created_at, expires_at, used) "
            "VALUES (?, ?, ?, ?, ?, 0)",
            (
                hashlib.sha256(code.encode("utf-8")).hexdigest(),
                agent_id,
                json.dumps(card),
                _iso(at),
                _iso(expires_at),
            ),
        )
    return {"code": code, "expires_at": _iso(expires_at)}


def verify_card_and_fingerprint(
    card: dict[str, Any], now: datetime | None = None
) -> tuple[str, str]:
    """Verify the card signature LOCALLY; return (agent_id, fingerprint).

    The fingerprint is derived from the verified card's public key, never
    from relay metadata. Raises PairingError on any fault.
    """
    from app.identity import crypto
    from relay.directory import verify_card

    try:
        verify_card(card)
    except Exception as exc:
        code = getattr(exc, "code", "INVALID_CARD")
        status = getattr(exc, "status", 401)
        raise PairingError(code, str(exc), status=status) from exc
    try:
        public_raw = base64.b64decode(
            card["public_key"].encode("ascii"), validate=True
        )
        crypto.load_public_key(public_raw)
    except Exception as exc:
        raise PairingError(
            "INVALID_CARD", "card public key is not valid.", status=401
        ) from exc
    return card["agent_id"], crypto.fingerprint_from_public_key(public_raw)


def claim_invite(
    conn: sqlite3.Connection,
    code: str,
    *,
    now: datetime | None = None,
    claim_fn: Callable[[str], dict[str, Any]],
) -> dict[str, Any]:
    """Claim a code: local cooldown -> relay fetch -> local verify.

    Returns the trust-screen payload (verified-card fields only).
    ``claim_fn`` maps the code to the relay's card or raises PairingError.
    """
    at = now or _utcnow()
    normalized = normalize_code(code)
    _check_local_cooldown(conn, at)
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    local = conn.execute(
        "SELECT used, expires_at FROM invites WHERE code_hash = ?",
        (digest,),
    ).fetchone()
    if local is not None:
        expires = _parse(local["expires_at"])
        if int(local["used"]):
            raise PairingError(
                "ALREADY_CLAIMED", "invite already claimed.", status=409
            )
        if expires is not None and at >= expires:
            raise PairingError(
                "EXPIRED",
                "invite expired; ask the inviter for a new code.",
                status=410,
            )
    try:
        card = claim_fn(normalized)
    except PairingError as exc:
        if exc.code == "INVALID_CODE":
            _record_local_failure(conn, at)
        raise
    agent_id, fingerprint = verify_card_and_fingerprint(card)
    _clear_local_failures(conn)
    return {
        "agent_id": agent_id,
        "display_name": card.get("display_name", ""),
        "fingerprint": fingerprint,
        "card": card,
    }


def approve_peer(
    conn: sqlite3.Connection, card: dict[str, Any], now: datetime | None = None
) -> dict[str, Any]:
    """Mutual-approve step: re-verify the card, then pin the key."""
    at = now or _utcnow()
    agent_id, fingerprint = verify_card_and_fingerprint(card)
    with conn:
        conn.execute(
            "INSERT OR REPLACE INTO paired_peers "
            "(agent_id, public_key, display_name, fingerprint, "
            "card_json, paired_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                agent_id,
                card["public_key"],
                card.get("display_name", ""),
                fingerprint,
                json.dumps(card),
                _iso(at),
            ),
        )
    return {
        "agent_id": agent_id,
        "public_key": card["public_key"],
        "display_name": card.get("display_name", ""),
        "fingerprint": fingerprint,
        "paired_at": _iso(at),
    }


def list_peers(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT agent_id, public_key, display_name, fingerprint, paired_at "
        "FROM paired_peers ORDER BY agent_id ASC"
    ).fetchall()
    return [dict(row) for row in rows]


def get_peer(conn: sqlite3.Connection, agent_id: str) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT agent_id, public_key, display_name, fingerprint, paired_at "
        "FROM paired_peers WHERE agent_id = ?",
        (agent_id,),
    ).fetchone()
    return dict(row) if row is not None else None


def unpair(conn: sqlite3.Connection, agent_id: str) -> bool:
    """Remove a peer locally. Pure SQLite: no network, always works."""
    with conn:
        cursor = conn.execute(
            "DELETE FROM paired_peers WHERE agent_id = ?", (agent_id,)
        )
    return cursor.rowcount > 0


def _raise_for_relay_response(status: int, body: Any) -> PairingError:
    if isinstance(body, dict):
        code = body.get("code", "UNKNOWN") or "UNKNOWN"
        detail = body.get("detail", "relay request failed.") or "failed"
    else:
        code, detail = "UNKNOWN", "relay request failed."
    return PairingError(code, detail, status=status)


def http_publish_transport(base_url: str):
    """Publish transport over HTTP (used by the API route)."""
    import httpx

    def publish(code: str, card: dict[str, Any]) -> dict[str, Any]:
        resp = httpx.post(
            f"{base_url.rstrip('/')}/invites",
            json={"code": code, "card": card},
            timeout=10,
        )
        try:
            body = resp.json()
        except ValueError:
            body = None
        if resp.status_code != 200:
            raise _raise_for_relay_response(resp.status_code, body)
        return body

    return publish


def http_claim_transport(base_url: str):
    """Claim transport over HTTP (used by the API route)."""
    import httpx

    def claim(code: str) -> dict[str, Any]:
        resp = httpx.post(
            f"{base_url.rstrip('/')}/invites/claim",
            json={"code": code},
            timeout=10,
        )
        try:
            body = resp.json()
        except ValueError:
            body = None
        if resp.status_code != 200:
            raise _raise_for_relay_response(resp.status_code, body)
        if not isinstance(body, dict) or "card" not in body:
            raise PairingError("INVALID_CARD", "relay returned no card.")
        return body["card"]

    return claim


__all__ = [
    "CODE_WORDS",
    "COOLDOWN_SECONDS",
    "INVITE_TTL_SECONDS",
    "MAX_CLAIM_ATTEMPTS",
    "WORDLIST",
    "PairingError",
    "approve_peer",
    "claim_invite",
    "code_hash",
    "create_invite",
    "generate_code",
    "get_peer",
    "http_claim_transport",
    "http_publish_transport",
    "list_peers",
    "normalize_code",
    "unpair",
    "verify_card_and_fingerprint",
]
