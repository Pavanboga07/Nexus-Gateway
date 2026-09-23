"""V2 envelope tests (v0.3, TDD red first).

Covers the frozen v0.3 rules: canonical serialization (strict UTC
timestamps, floats rejected, signature excluded, None omitted at every
level), sign/verify round-trip, tamper failure, expiry rejection,
unknown-type rejection, and signed error envelopes. Byte-exact vectors
live in tests/vectors/envelope.json.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

VECTORS_PATH = Path(__file__).parent / "vectors" / "envelope.json"


def load_vectors() -> dict:
    return json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


def by_name(entries, name: str) -> dict:
    for entry in entries:
        if entry["name"] == name:
            return entry
    raise AssertionError(f"vector {name!r} missing")


def test_vectors_file_has_valid_and_rejection_cases():
    data = load_vectors()
    names = {v["name"] for v in data["vectors"]}
    assert "request-with-correlation" in names
    assert "approve-reply" in names
    rej = {r["name"] for r in data["rejections"]}
    assert {"float-payload", "bad-timestamp", "unknown-type"} <= rej


def test_vector_canonical_bytes_match_exactly():
    from relay.envelope import Envelope

    data = load_vectors()
    for entry in data["vectors"]:
        env = Envelope.model_validate(entry["envelope"])
        assert env.canonical_bytes().hex() == entry["canonical_hex"]


def test_vector_signatures_verify_under_recorded_keys():
    from relay.envelope import verify_envelope_signature

    data = load_vectors()
    for entry in data["vectors"]:
        assert entry["verifies"] is True
        assert (
            verify_envelope_signature(
                entry["envelope"], entry["public_key"]
            )
            is True
        )


def test_tampered_vector_payload_fails_verify():
    from relay.envelope import verify_envelope_signature

    data = load_vectors()
    entry = by_name(data["vectors"], "request-with-correlation")
    tampered = json.loads(json.dumps(entry["envelope"]))
    tampered["payload"] = {"action": "forged"}
    assert (
        verify_envelope_signature(tampered, entry["public_key"]) is False
    )


def test_sign_verify_round_trip_with_fresh_key():
    from relay.envelope import sign_envelope, verify_envelope_signature
    from tests.relay_db import make_envelope, new_agent

    priv, pub_b64, agent_id = new_agent()
    _, _, peer_id = new_agent()
    unsigned = make_envelope(sender=agent_id, recipient=peer_id)
    signed = sign_envelope(priv, unsigned)
    assert signed["signature"]
    assert verify_envelope_signature(signed, pub_b64) is True


def test_rejection_vectors_raise_matching_errors():
    from relay.envelope import CanonicalizationError, EnvelopeError

    data = load_vectors()
    for entry in data["rejections"]:
        # Rejection inputs fail at canonicalization (floats, a TypeError)
        # or at schema validation (timestamps, types, a ValueError).
        with pytest.raises((ValueError, CanonicalizationError)) as exc:
            _validate_raw(entry["envelope"])
        assert entry["error_hint"] in str(exc.value).lower()


def _validate_raw(raw: dict):
    from relay.envelope import Envelope, canonical_json_bytes

    # Rejection inputs may fail at canonicalization (floats) or at
    # schema validation (timestamps, unknown types) — either rejects.
    canonical_json_bytes({k: v for k, v in raw.items() if k != "signature"})
    Envelope.model_validate(raw)


def test_expired_envelope_rejected():
    from relay.envelope import Envelope, EnvelopeError
    from tests.relay_db import make_envelope, new_agent

    _, _, a = new_agent()
    _, _, b = new_agent()
    raw = make_envelope(
        sender=a,
        recipient=b,
        timestamp="2026-09-20T12:00:00Z",
        expires_at="2026-09-20T12:01:00Z",
    )
    with pytest.raises(EnvelopeError) as exc:
        Envelope.validate_live(raw, now="2026-09-20T12:02:00Z")
    assert "expired" in str(exc.value).lower()


def test_unknown_message_type_builds_signed_error():
    from relay.envelope import build_signed_error, verify_envelope_signature
    from tests.relay_db import new_agent

    priv, pub_b64, agent_id = new_agent()
    _, _, peer_id = new_agent()
    err = build_signed_error(
        priv,
        sender=agent_id,
        recipient=peer_id,
        correlation_id="corr_bad001",
        code="INVALID_ENVELOPE",
        message="unknown message_type 'teleport'",
    )
    assert err["message_type"] == "error"
    assert err["correlation_id"] == "corr_bad001"
    assert err["payload"]["code"] == "INVALID_ENVELOPE"
    assert verify_envelope_signature(err, pub_b64) is True


def test_signature_excluded_from_signed_bytes():
    from relay.envelope import Envelope

    data = load_vectors()
    entry = by_name(data["vectors"], "request-with-correlation")
    env = Envelope.model_validate(entry["envelope"])
    assert "signature" not in env.unsigned_dict()
    # Re-signing the unsigned dict reproduces identical canonical bytes.
    assert env.canonical_bytes().hex() == entry["canonical_hex"]
