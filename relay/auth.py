"""Ed25519 challenge-response auth. Challenges are single-use, short-lived, in Postgres."""

from __future__ import annotations

import base64
import os
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.identity import crypto
from relay.models import Challenge

CHALLENGE_BYTES = 32
CHALLENGE_TTL_SECONDS = 120


class AuthError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def new_challenge_bytes() -> bytes:
    return os.urandom(CHALLENGE_BYTES)


def encode_challenge(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def decode_challenge(encoded: str) -> bytes:
    try:
        raw = base64.b64decode(encoded.encode("ascii"), validate=True)
    except Exception as exc:
        raise AuthError("INVALID_CHALLENGE", "challenge is not base64") from exc
    if len(raw) != CHALLENGE_BYTES:
        raise AuthError("INVALID_CHALLENGE", "challenge must be 32 bytes")
    return raw


async def mint_challenge(session: AsyncSession) -> str:
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=CHALLENGE_TTL_SECONDS)
    await session.execute(delete(Challenge).where(Challenge.created_at < cutoff))
    encoded = encode_challenge(new_challenge_bytes())
    session.add(Challenge(challenge=encoded))
    await session.flush()
    return encoded


async def verify_and_consume(
    session: AsyncSession,
    *,
    challenge_b64: str,
    agent_id: str,
    public_key_b64: str,
    signature_b64: str,
) -> str:
    row = (await session.execute(select(Challenge).where(Challenge.challenge == challenge_b64))).scalar_one_or_none()
    if row is None:
        raise AuthError("INVALID_CHALLENGE", "unknown challenge")
    if row.used:
        raise AuthError("REPLAY", "challenge already consumed")
    created = row.created_at
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) - created > timedelta(seconds=CHALLENGE_TTL_SECONDS):
        raise AuthError("EXPIRED_CHALLENGE", "challenge expired")
    try:
        public_raw = base64.b64decode(public_key_b64.encode("ascii"), validate=True)
        public_key = crypto.load_public_key(public_raw)
        signature = base64.b64decode(signature_b64.encode("ascii"), validate=True)
        challenge_raw = base64.b64decode(challenge_b64.encode("ascii"), validate=True)
    except AuthError:
        raise
    except Exception as exc:
        raise AuthError("IDENTITY_MISMATCH", "public key or signature is not base64") from exc
    if crypto.agent_id_from_public_key(public_raw) != agent_id:
        raise AuthError("IDENTITY_MISMATCH", "agent_id is not the key fingerprint")
    if not crypto.verify_bytes(public_key, challenge_raw, signature):
        raise AuthError("INVALID_SIGNATURE", "challenge signature invalid")
    row.used = True
    row.agent_id = agent_id
    await session.flush()
    return agent_id


__all__ = [
    "CHALLENGE_BYTES",
    "CHALLENGE_TTL_SECONDS",
    "AuthError",
    "decode_challenge",
    "encode_challenge",
    "mint_challenge",
    "new_challenge_bytes",
    "verify_and_consume",
]
