"""Agent card directory: verified writes, atomic handles, paginated reads, rate limited."""

from __future__ import annotations

import base64
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import delete, func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from relay import crypto
from relay.envelope import AGENT_ID_PATTERN, TIMESTAMP_PATTERN, canonical_json_bytes, parse_iso
from relay.models import DirectoryEntry, RateHit

CARD_TYPE = "agent-card"
CARD_PROTOCOL = "nexus-a2a"
CARD_VERSION = "0.3"
MAX_CLOCK_SKEW_SECONDS = 30.0
RATE_WINDOW_SECONDS = 60.0
LIST_LIMIT_DEFAULT = 50
LIST_LIMIT_MAX = 100

HANDLE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.\-]{1,31}$")

REQUIRED_CARD_FIELDS = frozenset({
    "type", "protocol", "version", "agent_id", "display_name",
    "public_key", "endpoint", "capabilities", "supported_purposes",
    "issued_at", "expires_at", "signature",
})


class DirectoryError(ValueError):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


def validate_card_schema(card: dict[str, Any]) -> None:
    if not isinstance(card, dict):
        raise DirectoryError(401, "INVALID_CARD", "card must be a JSON object")
    missing = REQUIRED_CARD_FIELDS - set(card.keys())
    if missing:
        raise DirectoryError(401, "INVALID_CARD", f"card is missing fields: {', '.join(sorted(missing))}")
    if card.get("type") != CARD_TYPE:
        raise DirectoryError(401, "INVALID_CARD", "card type must be agent-card")
    if card.get("protocol") != CARD_PROTOCOL:
        raise DirectoryError(401, "INVALID_CARD", "card protocol mismatch")
    if card.get("version") != CARD_VERSION:
        raise DirectoryError(401, "INVALID_CARD", f"card version must be {CARD_VERSION}")
    agent_id = card.get("agent_id", "")
    if not isinstance(agent_id, str) or not AGENT_ID_PATTERN.fullmatch(agent_id):
        raise DirectoryError(401, "INVALID_CARD", "card agent_id is malformed")
    for field in ("display_name", "public_key", "endpoint", "signature"):
        if not isinstance(card.get(field), str) or not card[field]:
            raise DirectoryError(401, "INVALID_CARD", f"card {field} must be a non-empty string")
    for field in ("issued_at", "expires_at"):
        value = card.get(field, "")
        if not isinstance(value, str) or not TIMESTAMP_PATTERN.fullmatch(value):
            raise DirectoryError(401, "INVALID_CARD", f"card {field} must be UTC ISO-8601 (YYYY-MM-DDTHH:MM:SSZ)")
    if not isinstance(card.get("capabilities"), list):
        raise DirectoryError(401, "INVALID_CARD", "capabilities must be a list")
    if not isinstance(card.get("supported_purposes"), list):
        raise DirectoryError(401, "INVALID_CARD", "supported_purposes must be a list")
    handle = card.get("handle")
    if handle is not None and (not isinstance(handle, str) or not HANDLE_PATTERN.fullmatch(handle)):
        raise DirectoryError(401, "INVALID_CARD", "card handle is malformed")
    try:
        canonical_json_bytes({k: v for k, v in card.items()})
    except TypeError as exc:
        raise DirectoryError(401, "INVALID_CARD", f"card is not signable: {exc}") from exc


def verify_card(card: dict[str, Any], *, now: datetime | None = None) -> None:
    validate_card_schema(card)
    try:
        public_raw = base64.b64decode(card["public_key"].encode("ascii"), validate=True)
        public_key = crypto.load_public_key(public_raw)
        signature = base64.b64decode(card["signature"].encode("ascii"), validate=True)
    except DirectoryError:
        raise
    except Exception as exc:
        raise DirectoryError(401, "INVALID_CARD", "card key material is not valid base64") from exc
    if crypto.agent_id_from_public_key(public_raw) != card["agent_id"]:
        raise DirectoryError(401, "IDENTITY_MISMATCH", "card agent_id is not the public key fingerprint")
    unsigned = {k: v for k, v in card.items() if k != "signature"}
    if not crypto.verify_bytes(public_key, canonical_json_bytes(unsigned), signature):
        raise DirectoryError(401, "INVALID_SIGNATURE", "card signature does not verify")
    at = now or datetime.now(timezone.utc)
    issued = parse_iso(card["issued_at"])
    expires = parse_iso(card["expires_at"])
    if expires <= issued:
        raise DirectoryError(401, "INVALID_CARD", "card expires_at must be after issued_at")
    if expires <= at:
        raise DirectoryError(401, "CARD_EXPIRED", "card has expired")
    if (issued - at).total_seconds() > MAX_CLOCK_SKEW_SECONDS:
        raise DirectoryError(401, "INVALID_CARD", "card issued_at is too far in the future")


def sign_card(private_key, card: dict[str, Any]) -> dict[str, Any]:
    unsigned = {k: v for k, v in card.items() if k != "signature"}
    raw_sig = crypto.sign_bytes(private_key, canonical_json_bytes(unsigned))
    return {**unsigned, "signature": base64.b64encode(raw_sig).decode("ascii")}


async def check_rate_limit(session: AsyncSession, ip: str, *, limit: int, window_seconds: float = RATE_WINDOW_SECONDS) -> None:
    """Atomically record this attempt and enforce the write rate limit.

    The hit is INSERTed and counted in a single statement, so concurrent
    bursts cannot slip through the check-then-insert race. Callers must
    commit the session even when this raises: the rejected attempt still
    burns budget, and the hit must be recorded BEFORE any validation
    runs (in a separate transaction) so failed validations cannot roll
    it back.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
    await session.execute(delete(RateHit).where(RateHit.created_at < cutoff))
    count = (
        await session.execute(
            text(
                "WITH new_hit AS ("
                " INSERT INTO rate_hits (ip) VALUES (:ip) RETURNING id"
                ") SELECT count(*) FROM rate_hits"
                " WHERE ip = :ip AND created_at >= :cutoff"
            ),
            {"ip": ip, "cutoff": cutoff},
        )
    ).scalar_one()
    await session.flush()
    if count > limit:
        raise DirectoryError(429, "RATE_LIMITED", "directory write rate limit exceeded")


async def get_entry(session: AsyncSession, agent_id: str) -> dict[str, Any] | None:
    row = (
        await session.execute(
            select(DirectoryEntry).where(DirectoryEntry.agent_id == agent_id, _fresh_filter())
        )
    ).scalar_one_or_none()
    if row is None:
        return None
    return dict(row.card)


async def store_entry(session: AsyncSession, card: dict[str, Any]) -> str:
    verify_card(card)
    agent_id = card["agent_id"]
    handle = card.get("handle")
    if handle is not None:
        owner = (await session.execute(select(DirectoryEntry.agent_id).where(DirectoryEntry.handle == handle))).scalar_one_or_none()
        if owner is not None and owner != agent_id:
            raise DirectoryError(409, "HANDLE_CONFLICT", f"handle {handle!r} is already claimed")
    try:
        existing = (await session.execute(select(DirectoryEntry).where(DirectoryEntry.agent_id == agent_id))).scalar_one_or_none()
        if existing is None:
            session.add(DirectoryEntry(agent_id=agent_id, handle=handle, public_key=card["public_key"], display_name=card["display_name"], card=dict(card), signature=card["signature"]))
        else:
            existing.handle = handle
            existing.public_key = card["public_key"]
            existing.display_name = card["display_name"]
            existing.card = dict(card)
            existing.signature = card["signature"]
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        raise DirectoryError(409, "HANDLE_CONFLICT", f"handle {handle!r} is already claimed") from exc
    return "stored"


async def list_entries(session: AsyncSession, *, limit: int = LIST_LIMIT_DEFAULT, offset: int = 0) -> tuple[int, list[dict[str, Any]]]:
    limit = max(1, min(limit, LIST_LIMIT_MAX))
    offset = max(0, offset)
    fresh = _fresh_filter()
    total = (await session.execute(select(func.count()).select_from(DirectoryEntry).where(fresh))).scalar_one()
    rows = (await session.execute(select(DirectoryEntry).where(fresh).order_by(DirectoryEntry.agent_id.asc()).limit(limit).offset(offset))).scalars().all()
    items = [{"agent_id": row.agent_id, "handle": row.handle, "display_name": row.display_name} for row in rows]
    return total, items


def _fresh_filter():
    """SQL predicate: card not yet expired.

    ``expires_at`` is write-validated to fixed-width ``YYYY-MM-DDTHH:MM:SSZ``,
    so lexicographic comparison against "now" in the same format is exact.
    """
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return DirectoryEntry.card["expires_at"].astext > now_iso


async def purge_old_rate_hits(session: AsyncSession, *, older_than_seconds: float = 86400) -> int:
    """Delete rate-limit hits older than the retention window. Returns rows removed."""
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=older_than_seconds)
    result = await session.execute(delete(RateHit).where(RateHit.created_at < cutoff))
    await session.flush()
    return result.rowcount or 0
