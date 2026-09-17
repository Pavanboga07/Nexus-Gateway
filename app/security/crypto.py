"""
Standalone cryptographic operations for the Nexus Gateway.

This module provides Ed25519 signature verification and agent ID generation.
It explicitly avoids importing from internal Nexus modules.
"""
from __future__ import annotations

import base64
import hashlib
import os
import logging
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger(__name__)

AGENT_ID_PREFIX = "nexus:ed25519:"
AGENT_ID_HASH_BYTES = 16

def generate_challenge(num_bytes: int = 32) -> bytes:
    """Generate random challenge bytes for authentication."""
    return os.urandom(num_bytes)

def verify_signature(public_key_b64: str, data: bytes, signature_b64: str) -> bool:
    """
    Verify an Ed25519 signature.

    Args:
        public_key_b64: Base64-encoded raw 32-byte Ed25519 public key.
        data: The signed data as bytes.
        signature_b64: Base64-encoded signature.

    Returns:
        True if the signature is valid, False otherwise.
    """
    try:
        public_key_bytes = base64.b64decode(public_key_b64)
        if len(public_key_bytes) != 32:
            return False
            
        signature_bytes = base64.b64decode(signature_b64)
        if len(signature_bytes) != 64:
            return False

        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature_bytes, data)
        return True
    except Exception as exc:
        # Deliberately broad: this is a verification boundary and must never
        # raise into the caller. (An earlier revision listed
        # `(ValueError, TypeError, InvalidSignature, Exception)`, which is
        # both redundant and flagged by linters.)
        logger.debug("Signature verification failed: %s", exc)
        return False

def agent_id_from_public_key_bytes(public_key_raw: bytes) -> str:
    """Compute agent_id from raw 32-byte public key."""
    digest = hashlib.sha256(public_key_raw).digest()
    fingerprint = digest[:AGENT_ID_HASH_BYTES].hex()
    return f"{AGENT_ID_PREFIX}{fingerprint}"

def agent_id_from_public_key_b64(public_key_b64: str) -> str:
    """Compute agent_id from a base64-encoded public key."""
    try:
        public_key_raw = base64.b64decode(public_key_b64)
        return agent_id_from_public_key_bytes(public_key_raw)
    except (ValueError, TypeError):
        return ""

def agent_id_matches_key(agent_id: str, public_key_b64: str) -> bool:
    """Check if the agent_id matches the public key."""
    expected_id = agent_id_from_public_key_b64(public_key_b64)
    return bool(expected_id) and agent_id == expected_id
