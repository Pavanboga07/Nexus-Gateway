"""Tests for security boundaries, spoofing prevention, and envelope validation."""

from __future__ import annotations

import pytest

from app.security.validation import (
    validate_envelope_structure,
    validate_relay_sender,
)
from tests.conftest import TestAgentIdentity


def test_valid_envelope_passes_structure_validation(
    agent_alice: TestAgentIdentity, agent_bob: TestAgentIdentity
) -> None:
    """A standard compliant A2A envelope structure passes validation."""
    env = agent_alice.make_envelope(recipient_id=agent_bob.agent_id)
    valid, err = validate_envelope_structure(env)
    assert valid is True
    assert err is None


def test_malformed_envelope_rejected() -> None:
    """Envelopes missing mandatory fields or having invalid protocol are rejected."""
    # Missing fields
    valid, err = validate_envelope_structure({"protocol": "nexus-a2a"})
    assert valid is False
    assert "Invalid or missing" in err

    # Wrong protocol
    valid, err = validate_envelope_structure({
        "protocol": "other-protocol",
        "version": "0.1",
        "message_id": "msg_123",
        "task_id": "task_123",
        "sender": "nexus:ed25519:0123456789abcdef0123456789abcdef",
        "recipient": "nexus:ed25519:abcdef0123456789abcdef0123456789",
        "timestamp": "2026-09-15T10:00:00Z",
        "expires_at": "2026-09-15T10:01:00Z",
        "message_type": "request",
        "purpose": "test",
        "payload": {},
    })
    assert valid is False
    assert "Invalid or missing protocol" in err

    # Bad agent_id pattern
    valid, err = validate_envelope_structure({
        "protocol": "nexus-a2a",
        "version": "0.1",
        "message_id": "msg_123",
        "task_id": "task_123",
        "sender": "not_an_agent_id",
        "recipient": "nexus:ed25519:abcdef0123456789abcdef0123456789",
        "timestamp": "2026-09-15T10:00:00Z",
        "expires_at": "2026-09-15T10:01:00Z",
        "message_type": "request",
        "purpose": "test",
        "payload": {},
    })
    assert valid is False
    assert "Invalid or missing sender ID" in err


def test_sender_spoofing_check(
    agent_alice: TestAgentIdentity, agent_bob: TestAgentIdentity
) -> None:
    """validate_relay_sender verifies that envelope['sender'] matches the authenticated connection."""
    env_alice = agent_alice.make_envelope(recipient_id=agent_bob.agent_id)

    # Legitimate sender: Alice connects and sends envelope with sender=Alice
    valid, err = validate_relay_sender(env_alice, agent_alice.agent_id)
    assert valid is True
    assert err is None

    # Spoofed sender: Alice connects, but sends envelope claiming sender=Bob
    valid, err = validate_relay_sender(env_alice, agent_bob.agent_id)
    assert valid is False
    assert "does not match authenticated agent" in err
