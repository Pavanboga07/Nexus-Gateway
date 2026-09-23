"""Agent card directory (REST writes, Postgres backed).

Write path (every write, unconditionally):

1. schema check (required fields, patterns, no floats);
2. ``agent_id`` == fingerprint of ``public_key`` (self-certifying);
3. Ed25519 signature verifies over canonical unsigned card bytes;
4. time window valid (``issued_at`` <= now < ``expires_at``).

Any failure -> 401 and nothing is stored. Handle claims are atomic:
the UNIQUE(handle) constraint is the arbiter and an integrity conflict
surfaces as a clean 409 (never a 500). Reads are paginated; writes are
per-IP rate limited. Write responses never echo the card back.
"""

from __future__ import annotations

import base64
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.identity import crypto
from relay.envelope import (
    TIMESTAMP_FORMAT,
    TIMESTAMP_PATTERN,
    canonical_json_bytes,
    parse_iso,
)
from relay.models import DirectoryEntry, RateHit

CARD_TYPE = "agent-card"
CARD_PROTOCOL = "nexus-a2a"
CARD_VERSION = "0.3"
MAX_CLOCK_SKEW_SECONDS = 30.0
RATE_WINDOW_SECONDS = 60.0
LIST_LIMIT_DEFAULT = 50
LIST_LIMIT_MAX = 100

HANDLE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.\-]{1,31}$")

REQUIRED_CARD_FIELDS = frozenset(
    {
        "type",
        "protocol",
        "version",
        "agent_id",
        "display_name",
        "public_key",
        "endpoint",
        "capabilities",
        "supported_purposes",
        "issued_at",
        "expires_at",
        "signature",
    }
)
AGENT_ID_PATTERN = re.compile(r"^nexus:ed25519:[0-9a-f]{32}$")


class DirectoryError(ValueError):
    """Directory failure with HTTP ``status`` and machine ``code``."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


def validate_card_schema(card: dict[str, Any]) -> None:
    if not isinstance(card, dict):
        raise DirectoryError(401, "INVALID_CARD", "card must be a JSON object")
    missing = REQUIRED_CARD_FIELDS - set(card.keys())
    if missing:
        raise DirectoryError(
            401, "INVALID_CARD",
            f"card is missing fields: {', '.join(sorted(missing))}",
        )
    if card.get("type") != CARD_TYPE:
        raise DirectoryError(401, "INVALID_CARD", "card type must be agent-card")
    if card.get("protocol") != CARD_PROTOCOL:
        raise DirectoryError(401, "INVALID_CARD", "card protocol mismatch")
    if card.get("version") != CARD_VERSION:
        raise DirectoryError(
            401, "INVALID_CARD", f"card version must be {CARD_VERSION}"
        )
    agent_id = card.get("agent_id", "")
    if not isinstance(agent_id, str) or not AGENT_ID_PATTERN.fullmatch(agent_id):
        raise DirectoryError(401, "INVALID_CARD", "card agent_id is malformed")
    for field in ("display_name", "public_key", "endpoint", "signature"):
        if not isinstance(card.get(field), str) or not card[field]:
            raise DirectoryError(
                401, "INVALID_CARD", f"card {field} must be a non-empty string"
            )
    for field in ("issued_at", "expires_at"):
        value = card.get(field, "")
        if not isinstance(value, str) or not TIMESTAMP_PATTERN.fullmatch(value):
            raise DirectoryError(
                401, "INVALID_CARD",
                f"card {field} must be UTC ISO-8601 (YYYY-MM-DDTHH:MM:SSZ)",
            )
    if not isinstance(card.get("capabilities"), list):
        raise DirectoryError(401, "INVALID_CARD", "capabilities must be a list")
    if not isinstance(card.get("supported_purposes"), list):
        raise DirectoryError(
            401, "INVALID_CARD", "supported_purposes must be a list"
        )
    handle = card.get("handle")
    if handle is not None and (
        not isinstance(handle, str) or not HANDLE_PATTERN.fullmatch(handle)
    ):
        raise DirectoryError(401, "INVALID_CARD", "card handle is malformed")
    try:
        canonical_json_bytes({k: v for k, v in card.items()})
    except TypeError as exc:
        raise DirectoryError(
            401, "INVALID_CARD", f"card is not signable: {exc}"
        ) from exc


def verify_card(card: dict[str, Any], *, now: datetime | None = None) -> None:
    """All four card checks in order; raises DirectoryError (401) on fault."""
    validate_card_schema(card)
    try:
        public_raw = base64.b64decode(
            card["public_key"].encode("ascii"), validate=True
        )
        public_key = crypto.load_public_key(public_raw)
        signature = base64.b64decode(
            card["signature"].encode("ascii"), validate=True
        )
    except DirectoryError:
        raise
    except Exception as exc:
        raise DirectoryError(
            401, "INVALID_CARD", "card key material is not valid base64"
        ) from exc
    if crypto.agent_id_from_public_key(public_raw) != card["agent_id"]:
        raise DirectoryError(
            401, "IDENTITY_MISMATCH",
            "card agent_id is not the public key fingerprint",
        )
    unsigned = {k: v for k, v in card.items() if k != "signature"}
    if not crypto.verify_bytes(
        public_key, canonical_json_bytes(unsigned), signature
    ):
        raise DirectoryError(
            401, "INVALID_SIGNATURE", "card signature does not verify"
        )
    at = now or datetime.now(timezone.utc)
    issued = parse_iso(card["issued_at"])
    expires = parse_iso(card["expires_at"])
    if expires <= issued:
        raise DirectoryError(
            401, "INVALID_CARD", "card expires_at must be after issued_at"
        )
    if expires <= at:
        raise DirectoryError(401, "CARD_EXPIRED", "card has expired")
    if (issued - at).total_seconds() > MAX_CLOCK_SKEW_SECONDS:
        raise DirectoryError(
            401, "INVALID_CARD", "card issued_at is too far in the future"
        )


def sign_card(private_key, card: dict[str, Any]) -> dict[str, Any]:
    """Attach a signature over the canonical unsigned card (test/edge use)."""
    unsigned = {k: v for k, v in card.items() if k != "signature"}
    raw_sig = crypto.sign_bytes(
        private_key, canonical_json_bytes(unsigned)
    )
    return {
        **unsigned,
        "signature": base64.b64encode(raw_sig).decode("ascii"),
    }


async def check_rate_limit(
    session: AsyncSession,
    ip: str,
    *,
    limit: int,
    window_seconds: float = RATE_WINDOW_SECONDS,
) -> None:
    """Per-IP write budget; raises DirectoryError(429) when exhausted."""
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
    await session.execute(
        delete(RateHit).where(RateHit.created_at < cutoff)
    )
    count = (
        await session.execute(
            select(func.count()).where(RateHit.ip == ip)
        )
    ).scalar_one()
    if count >= limit:
        raise DirectoryError(
            429, "RATE_LIMITED", "directory write rate limit exceeded"
        )
    session.add(RateHit(ip=ip))
    await session.flush()


async def get_entry(
    session: AsyncSession, agent_id: str
) -> dict[str, Any] | None:
    """The stored card for one agent; None when unknown."""
    row = (
        await session.execute(
            select(DirectoryEntry).where(
                DirectoryEntry.agent_id == agent_id
            )
        )
    ).scalar_one_or_none()
    if row is None:
        return None
    return dict(row.card)


async def store_entry(session: AsyncSession, card: dict[str, Any]) -> str:
    """Verify unconditionally, then insert-or-update. Returns ``"stored"``.

    Handle claims are atomic: a pre-check gives the clean 409 fast path
    and the UNIQUE(handle) constraint is the arbiter under races (an
    IntegrityError also surfaces as 409, never 500). The same agent may
    always reclaim its own handle.
    """
    verify_card(card)
    agent_id = card["agent_id"]
    handle = card.get("handle")
    if handle is not None:
        owner = (
            await session.execute(
                select(DirectoryEntry.agent_id).where(
                    DirectoryEntry.handle == handle
                )
            )
        ).scalar_one_or_none()
        if owner is not None and owner != agent_id:
            raise DirectoryError(
                409, "HANDLE_CONFLICT",
                f"handle {handle!r} is already claimed",
            )
    try:
        existing = (
            await session.execute(
                select(DirectoryEntry).where(
                    DirectoryEntry.agent_id == agent_id
                )
            )
        ).scalar_one_or_none()
        if existing is None:
            session.add(
                DirectoryEntry(
                    agent_id=agent_id,
                    handle=handle,
                    public_key=card["public_key"],
                    display_name=card["display_name"],
                    card=dict(card),
                    signature=card["signature"],
                )
            )
        else:
            existing.handle = handle
            existing.public_key = card["public_key"]
            existing.display_name = card["display_name"]
            existing.card = dict(card)
            existing.signature = card["signature"]
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        raise DirectoryError(
            409, "HANDLE_CONFLICT",
            f"handle {handle!r} is already claimed",
        ) from exc
    return "stored"


async def list_entries(
    session: AsyncSession,
    *,
    limit: int = LIST_LIMIT_DEFAULT,
    offset: int = 0,
) -> tuple[int, list[dict[str, Any]]]:
    """Paginated ``(total, items)``; items never include full cards."""
    limit = max(1, min(limit, LIST_LIMIT_MAX))
    offset = max(0, offset)
    total = (
        await session.execute(select(func.count()).select_from(DirectoryEntry))
    ).scalar_one()
    rows = (
        await session.execute(
            select(DirectoryEntry)
            .order_by(DirectoryEntry.agent_id.asc())
            .limit(limit)
            .offset(offset)
        )
    ).scalars().all()
    items = [
        {
            "agent_id": row.agent_id,
            "handle": row.handle,
            "display_name": row.display_name,
        }
        for row in rows
    ]
    return total, items
