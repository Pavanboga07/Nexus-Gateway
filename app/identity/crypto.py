"""Ed25519 identity primitives (V1).

Self-certifying scheme (documented here so verifiers need no registry):

    agent_id = "nexus:ed25519:" + hex(SHA-256(raw 32-byte pubkey))[:32]

The id is deterministic from the public key: anyone holding the pubkey
recomputes the digest prefix and confirms the key belongs to the id.
The private key is never involved in the id. Fingerprint is the same
digest rendered for humans as 8x4 upper-hex groups.

Private keys at rest are AES-256-GCM sealed with a machine-local secret
(never stored in the DB); the stored form is base64(nonce || ct+tag).
"""

from __future__ import annotations

import base64
import hashlib
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AGENT_ID_PREFIX = "nexus:ed25519:"
# First 16 digest bytes (32 hex chars): compact yet collision-resistant
# for a single-user-per-laptop registry.
AGENT_ID_HASH_BYTES = 16
AES_NONCE_BYTES = 12
FINGERPRINT_GROUPS = 8


class IdentityCryptoError(Exception):
    """Key, seal, or open failure."""


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def public_key_bytes(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def private_key_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_public_key(raw: bytes) -> Ed25519PublicKey:
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except Exception as exc:
        raise IdentityCryptoError("Invalid public key bytes.") from exc


def load_private_key(raw: bytes) -> Ed25519PrivateKey:
    try:
        return Ed25519PrivateKey.from_private_bytes(raw)
    except Exception as exc:
        raise IdentityCryptoError("Invalid private key bytes.") from exc


def agent_id_from_public_key(public_key_raw: bytes) -> str:
    digest = hashlib.sha256(public_key_raw).hexdigest()
    return f"{AGENT_ID_PREFIX}{digest[: AGENT_ID_HASH_BYTES * 2]}"


def fingerprint_from_public_key(public_key_raw: bytes) -> str:
    digest = hashlib.sha256(public_key_raw).hexdigest().upper()
    groups = [
        digest[i : i + 4] for i in range(0, FINGERPRINT_GROUPS * 4, 4)
    ]
    return "-".join(groups)


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


def _aes_key(secret: str) -> bytes:
    return hashlib.sha256(secret.encode("utf-8")).digest()


def encrypt_private_key(private_key_raw: bytes, secret: str) -> str:
    if not secret:
        raise IdentityCryptoError("Identity encryption secret is empty.")
    nonce = os.urandom(AES_NONCE_BYTES)
    ct = AESGCM(_aes_key(secret)).encrypt(nonce, private_key_raw, None)
    return base64.b64encode(nonce + ct).decode("ascii")


def decrypt_private_key(encrypted: str, secret: str) -> bytes:
    if not secret:
        raise IdentityCryptoError("Identity encryption secret is empty.")
    try:
        blob = base64.b64decode(encrypted.encode("ascii"))
        nonce, ct = blob[:AES_NONCE_BYTES], blob[AES_NONCE_BYTES:]
        return AESGCM(_aes_key(secret)).decrypt(nonce, ct, None)
    except Exception as exc:
        raise IdentityCryptoError(
            "Could not decrypt the agent private key: wrong secret "
            "or corrupted stored material."
        ) from exc


def keypair_matches(
    private_key: Ed25519PrivateKey, public_key: Ed25519PublicKey
) -> bool:
    return public_key_bytes(private_key.public_key()) == public_key_bytes(
        public_key
    )


__all__ = [
    "AES_NONCE_BYTES",
    "AGENT_ID_HASH_BYTES",
    "AGENT_ID_PREFIX",
    "FINGERPRINT_GROUPS",
    "IdentityCryptoError",
    "agent_id_from_public_key",
    "decrypt_private_key",
    "encrypt_private_key",
    "fingerprint_from_public_key",
    "generate_keypair",
    "keypair_matches",
    "load_private_key",
    "load_public_key",
    "private_key_bytes",
    "public_key_bytes",
    "sign_bytes",
    "verify_bytes",
]
