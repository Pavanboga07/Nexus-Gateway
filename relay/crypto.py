"""Ed25519 identity primitives vendored for the relay.

Extracted from the Nexus ``app.identity`` package so this service is
self-contained: the gateway verifies signatures and derives agent IDs
but never generates, stores, or decrypts private keys (see the threat
model in the README). Only the functions the relay actually uses live
here; the private-key-at-rest helpers were deliberately left behind.

Self-certifying scheme::

    agent_id = "nexus:ed25519:" + hex(SHA-256(raw 32-byte pubkey))[:32]

The id is deterministic from the public key: anyone holding the pubkey
recomputes the digest prefix and confirms the key belongs to the id.
"""

from __future__ import annotations

import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

AGENT_ID_PREFIX = "nexus:ed25519:"
# First 16 digest bytes (32 hex chars): compact yet collision-resistant
# for a single-user-per-laptop registry.
AGENT_ID_HASH_BYTES = 16


class IdentityCryptoError(Exception):
    """Key or verification failure."""


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Fresh Ed25519 keypair (used by tests and provisioning scripts)."""
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def public_key_bytes(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def load_public_key(raw: bytes) -> Ed25519PublicKey:
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except Exception as exc:
        raise IdentityCryptoError("Invalid public key bytes.") from exc


def agent_id_from_public_key(public_key_raw: bytes) -> str:
    digest = hashlib.sha256(public_key_raw).hexdigest()
    return f"{AGENT_ID_PREFIX}{digest[: AGENT_ID_HASH_BYTES * 2]}"


def sign_bytes(private_key: Ed25519PrivateKey, data: bytes) -> bytes:
    return private_key.sign(data)


def verify_bytes(
    public_key: Ed25519PublicKey, data: bytes, signature: bytes
) -> bool:
    try:
        public_key.verify(signature, data)
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


__all__ = [
    "AGENT_ID_HASH_BYTES",
    "AGENT_ID_PREFIX",
    "IdentityCryptoError",
    "agent_id_from_public_key",
    "generate_keypair",
    "load_public_key",
    "public_key_bytes",
    "sign_bytes",
    "verify_bytes",
]
