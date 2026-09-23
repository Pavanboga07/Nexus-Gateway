"""Single-use invite claims for V3 pairing (relay arbiter).

The inviter publishes ``sha256(code) -> signed card`` with a 15-minute
expiry; the claimant redeems the code once for the card and verifies
the card signature LOCALLY (the relay checks shape + expiry on
publish, but trust comes from the claimant's own verification).
Brute force is capped: unknown codes count per-IP attempts, 5 within
the window -> 429 COOLDOWN. Distinct, safe outcomes: INVALID_CODE
(404), COOLDOWN (429), ALREADY_CLAIMED (409), EXPIRED (410, with a
regenerate hint). Consumed invites stay flagged so replays answer
"already claimed"; expired rows stay so replays answer "expired".
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from relay.directory import verify_card
from relay.models import ClaimAttempt, Invite

INVITE_TTL_SECONDS = 900  # 15 minutes
MAX_ATTEMPTS = 5
COOLDOWN_WINDOW_SECONDS = 300  # 5 minutes


class InviteClaimError(ValueError):
    """Invite failure with HTTP ``status`` and machine ``code``."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


async def create_invite_entry(
    session: AsyncSession,
    card: Any,
    code: Any,
    *,
    ttl_seconds: int = INVITE_TTL_SECONDS,
) -> datetime:
    """Validate the card + code, then (re)publish the invite."""
    from app.pairing import PairingError, normalize_code

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
    existing = (
        await session.execute(
            select(Invite).where(Invite.token_hash == token_hash)
        )
    ).scalar_one_or_none()
    if existing is None:
        session.add(
            Invite(
                token_hash=token_hash,
                agent_id=card["agent_id"],
                card=dict(card),
                created_at=at,
                expires_at=expires_at,
                used=False,
                attempts=0,
            )
        )
    else:
        existing.agent_id = card["agent_id"]
        existing.card = dict(card)
        existing.created_at = at
        existing.expires_at = expires_at
        existing.used = False
        existing.attempts = 0
    await session.flush()
    return expires_at


async def _recent_ip_attempts(session: AsyncSession, ip: str) -> int:
    cutoff = _utcnow() - timedelta(seconds=COOLDOWN_WINDOW_SECONDS)
    await session.execute(
        delete(ClaimAttempt).where(ClaimAttempt.created_at < cutoff)
    )
    return (
        await session.execute(
            select(func.count()).where(ClaimAttempt.ip == ip)
        )
    ).scalar_one()


async def claim_invite_entry(
    session: AsyncSession, code: Any, ip: str
) -> dict[str, Any]:
    """Redeem one code for its card (single-use consume)."""
    from app.pairing import PairingError, normalize_code

    if await _recent_ip_attempts(session, ip) >= MAX_ATTEMPTS:
        raise InviteClaimError(
            429, "COOLDOWN",
            "too many wrong codes; try again in a few minutes.",
        )
    try:
        normalized = normalize_code(code)
    except PairingError:
        session.add(ClaimAttempt(ip=ip))
        await session.flush()
        raise InviteClaimError(
            404, "INVALID_CODE", "invite code not recognized."
        )
    token_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    # Atomic consume: a single UPDATE that only matches a live, unclaimed
    # row. Concurrent claims serialize on the row lock; exactly one sees
    # a row back (correct under any isolation, no lock ordering concerns).
    # A miss falls through to the shared read below, so the loser of a
    # race lands on the existing ALREADY_CLAIMED path, not a copy of it.
    while True:
        now = _utcnow()
        card = (
            await session.execute(
                update(Invite)
                .where(
                    Invite.token_hash == token_hash,
                    Invite.used.is_(False),
                    Invite.expires_at > now,
                )
                .values(used=True, attempts=Invite.attempts + 1)
                .returning(Invite.card)
            )
        ).scalar_one_or_none()
        if card is not None:
            return dict(card)
        row = (
            await session.execute(
                select(Invite).where(Invite.token_hash == token_hash)
            )
        ).scalar_one_or_none()
        if row is None:
            session.add(ClaimAttempt(ip=ip))
            await session.flush()
            left = MAX_ATTEMPTS - await _recent_ip_attempts(session, ip)
            raise InviteClaimError(
                404, "INVALID_CODE",
                f"invite code not recognized ({max(0, left)} of "
                f"{MAX_ATTEMPTS} attempts left).",
            )
        if row.used:
            raise InviteClaimError(
                409, "ALREADY_CLAIMED", "invite already claimed."
            )
        expires = row.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if now >= expires:
            raise InviteClaimError(
                410, "EXPIRED",
                "invite expired; ask the inviter for a new code.",
            )
        # Live and unclaimed, yet the UPDATE missed: only a concurrent
        # republish slipping between the two statements can do that —
        # retry the atomic consume rather than double-consuming.


__all__ = [
    "COOLDOWN_WINDOW_SECONDS",
    "INVITE_TTL_SECONDS",
    "MAX_ATTEMPTS",
    "InviteClaimError",
    "claim_invite_entry",
    "create_invite_entry",
]
