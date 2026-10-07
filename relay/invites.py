"""Single-use invite claims. Relay is arbiter; claimant verifies card locally."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from relay.directory import verify_card
from relay.models import ClaimAttempt, Invite
from relay.pairing import PairingError, normalize_code

INVITE_TTL_SECONDS = 900
MAX_ATTEMPTS = 5
COOLDOWN_WINDOW_SECONDS = 300


class InviteClaimError(ValueError):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


async def create_invite_entry(session: AsyncSession, card: Any, code: Any, *, ttl_seconds: int = INVITE_TTL_SECONDS) -> datetime:
    try:
        normalized = normalize_code(code)
    except PairingError as exc:
        raise InviteClaimError(400, "INVALID_CODE", str(exc)) from exc
    if not isinstance(card, dict):
        raise InviteClaimError(400, "INVALID_CARD", "card must be a JSON object")
    try:
        verify_card(card)
    except Exception as exc:
        status = getattr(exc, "status", 401)
        code_name = getattr(exc, "code", "INVALID_CARD")
        raise InviteClaimError(status, code_name, str(exc)) from exc
    try:
        ttl = int(ttl_seconds)
    except (TypeError, ValueError):
        ttl = INVITE_TTL_SECONDS
    at = _utcnow()
    expires_at = at + timedelta(seconds=max(0, ttl))
    token_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    existing = (await session.execute(select(Invite).where(Invite.token_hash == token_hash))).scalar_one_or_none()
    if existing is None:
        session.add(Invite(token_hash=token_hash, agent_id=card["agent_id"], card=dict(card), created_at=at, expires_at=expires_at, used=False))
    else:
        existing.agent_id = card["agent_id"]
        existing.card = dict(card)
        existing.created_at = at
        existing.expires_at = expires_at
        existing.used = False
    await session.flush()
    return expires_at


async def _recent_ip_attempts(session: AsyncSession, ip: str) -> int:
    cutoff = _utcnow() - timedelta(seconds=COOLDOWN_WINDOW_SECONDS)
    await session.execute(delete(ClaimAttempt).where(ClaimAttempt.created_at < cutoff))
    return (await session.execute(select(func.count()).where(ClaimAttempt.ip == ip))).scalar_one()


async def record_claim_attempt(session: AsyncSession, ip: str) -> int:
    """Record a failed claim attempt; returns attempts remaining in the window.

    Callers must commit this session in its own transaction — it is
    invoked from the error path, where the main session is rolled back.
    """
    session.add(ClaimAttempt(ip=ip))
    await session.flush()
    return max(0, MAX_ATTEMPTS - await _recent_ip_attempts(session, ip))


async def claim_invite_entry(session: AsyncSession, code: Any, ip: str) -> dict[str, Any]:
    if await _recent_ip_attempts(session, ip) >= MAX_ATTEMPTS:
        raise InviteClaimError(429, "COOLDOWN", "too many wrong codes; try again in a few minutes.")
    try:
        normalized = normalize_code(code)
    except PairingError:
        raise InviteClaimError(404, "INVALID_CODE", "invite code not recognized.")
    token_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    while True:
        now = _utcnow()
        card = (await session.execute(update(Invite).where(Invite.token_hash == token_hash, Invite.used.is_(False), Invite.expires_at > now).values(used=True).returning(Invite.card))).scalar_one_or_none()
        if card is not None:
            return dict(card)
        row = (await session.execute(select(Invite).where(Invite.token_hash == token_hash))).scalar_one_or_none()
        if row is None:
            raise InviteClaimError(404, "INVALID_CODE", "invite code not recognized.")
        if row.used:
            raise InviteClaimError(409, "ALREADY_CLAIMED", "invite already claimed.")
        expires = row.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if now >= expires:
            raise InviteClaimError(410, "EXPIRED", "invite expired; ask the inviter for a new code.")


async def purge_expired_invites(session: AsyncSession) -> int:
    """Delete used or expired invites. Returns rows removed."""
    result = await session.execute(
        delete(Invite).where((Invite.used.is_(True)) | (Invite.expires_at <= func.now()))
    )
    await session.flush()
    return result.rowcount or 0


async def purge_old_claim_attempts(session: AsyncSession, *, older_than_seconds: float = 86400) -> int:
    """Delete claim attempts older than the retention window. Returns rows removed."""
    cutoff = _utcnow() - timedelta(seconds=older_than_seconds)
    result = await session.execute(delete(ClaimAttempt).where(ClaimAttempt.created_at < cutoff))
    await session.flush()
    return result.rowcount or 0


__all__ = [
    "COOLDOWN_WINDOW_SECONDS",
    "INVITE_TTL_SECONDS",
    "MAX_ATTEMPTS",
    "InviteClaimError",
    "claim_invite_entry",
    "create_invite_entry",
    "purge_expired_invites",
    "purge_old_claim_attempts",
    "record_claim_attempt",
]
