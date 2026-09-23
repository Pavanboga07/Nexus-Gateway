"""v0.3 signed message envelope (frozen for v1).

Wire fields (relay redesign spec, section 3)::

    protocol / version / message_id / correlation_id / sender /
    recipient / timestamp / expires_at / message_type / payload
    + signature (on the wire, excluded from the signed bytes)

Types: ``request``, ``response``, ``approval_request``, ``approve``,
``reject``, ``error``. ``correlation_id`` is REQUIRED in v0.3: it groups
one ask/approve/answer exchange across hops (Task V4 builds the loop on
this key).

Canonical bytes (carried-over proven rules, reimplemented fresh):

- JSON with sorted keys, compact separators, ``ensure_ascii=False``,
  UTF-8 encoding;
- floats rejected ANYWHERE (platform-dependent repr breaks signatures);
- the ``signature`` field excluded from the bytes it covers;
- ``None``-valued keys omitted recursively (absent is not null).

Timestamps are strict UTC second-resolution ``YYYY-MM-DDTHH:MM:SSZ``.
"""

from __future__ import annotations

import base64
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, field_validator

PROTOCOL = "nexus-a2a"
VERSION = "0.3"

MESSAGE_TYPES = (
    "request",
    "response",
    "approval_request",
    "approve",
    "reject",
    "error",
)

ID_PATTERN = re.compile(r"^[A-Za-z0-9_\-]{1,128}$")
AGENT_ID_PATTERN = re.compile(r"^nexus:ed25519:[0-9a-f]{32}$")
TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
ERROR_TTL_SECONDS = 300


class CanonicalizationError(TypeError):
    """A value cannot be canonically serialized (floats, NaN, odd types)."""


class EnvelopeError(ValueError):
    """A wire envelope is invalid, expired, or unverifiable."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def canonical_json_bytes(value: Any) -> bytes:
    """Deterministic UTF-8 JSON bytes; rejects floats and non-finite."""
    try:
        text = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise CanonicalizationError(
            f"value is not canonically serializable: {exc}"
        ) from exc
    _reject_floats(value)
    return text.encode("utf-8")


def _reject_floats(node: Any) -> None:
    if isinstance(node, float):
        raise CanonicalizationError(
            "floats are not allowed in signed structures "
            "(platform-dependent repr); use int or str"
        )
    if isinstance(node, dict):
        for value in node.values():
            _reject_floats(value)
    elif isinstance(node, (list, tuple)):
        for value in node:
            _reject_floats(value)


def _drop_none(node: Any) -> Any:
    """Recursively omit None-valued dict keys (absent is not null)."""
    if isinstance(node, dict):
        return {
            key: _drop_none(value)
            for key, value in node.items()
            if value is not None
        }
    if isinstance(node, list):
        return [_drop_none(item) for item in node]
    return node


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime(TIMESTAMP_FORMAT)


def utc_iso_in(seconds: float) -> str:
    future = datetime.now(timezone.utc) + timedelta(seconds=seconds)
    return future.strftime(TIMESTAMP_FORMAT)


def parse_iso(value: str) -> datetime:
    try:
        return datetime.strptime(value, TIMESTAMP_FORMAT).replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise EnvelopeError(
            "INVALID_ENVELOPE", f"timestamp {value!r} is not strict UTC"
        ) from exc


class Envelope(BaseModel):
    """The signed v0.3 message envelope."""

    model_config = ConfigDict(extra="forbid")

    protocol: Literal["nexus-a2a"] = PROTOCOL
    version: Literal["0.3"] = VERSION
    message_id: str
    correlation_id: str
    sender: str
    recipient: str
    timestamp: str
    expires_at: str
    message_type: Literal[
        "request", "response", "approval_request",
        "approve", "reject", "error",
    ]
    payload: dict[str, Any]
    signature: str | None = None

    @field_validator("message_id", "correlation_id")
    @classmethod
    def _valid_id(cls, value: str, info) -> str:
        if not ID_PATTERN.fullmatch(value):
            raise ValueError(f"{info.field_name} has an invalid format")
        return value

    @field_validator("sender", "recipient")
    @classmethod
    def _valid_agent_id(cls, value: str, info) -> str:
        if not AGENT_ID_PATTERN.fullmatch(value):
            raise ValueError(
                f"{info.field_name} must match nexus:ed25519:<32 hex chars>"
            )
        return value

    @field_validator("timestamp", "expires_at")
    @classmethod
    def _valid_timestamp(cls, value: str, info) -> str:
        if not TIMESTAMP_PATTERN.fullmatch(value):
            raise ValueError(
                f"{info.field_name} must be UTC ISO-8601 "
                "(YYYY-MM-DDTHH:MM:SSZ)"
            )
        parse_iso(value)  # reject impossible dates
        return value

    @field_validator("payload")
    @classmethod
    def _valid_payload(cls, value: dict[str, Any]) -> dict[str, Any]:
        try:
            _reject_floats(value)
        except CanonicalizationError as exc:
            raise ValueError(str(exc)) from exc
        return value

    @classmethod
    def validate_live(
        cls, raw: dict[str, Any], *, now: str | None = None
    ) -> "Envelope":
        """Validate schema AND the live time window (rejects expired)."""
        env = cls.model_validate(raw)
        at = parse_iso(now) if now is not None else datetime.now(timezone.utc)
        if parse_iso(env.expires_at) <= at:
            raise EnvelopeError("EXPIRED", "envelope expires_at is past")
        if parse_iso(env.expires_at) <= parse_iso(env.timestamp):
            raise EnvelopeError(
                "INVALID_ENVELOPE", "expires_at must be after timestamp"
            )
        return env

    def unsigned_dict(self) -> dict[str, Any]:
        """Everything except the signature: the bytes covered by it."""
        return _drop_none(self.model_dump(exclude={"signature"}))

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.unsigned_dict())


def sign_envelope(private_key, unsigned: dict[str, Any]) -> dict[str, Any]:
    """Validate ``unsigned``, sign its canonical bytes, attach signature."""
    from app.identity import crypto

    env = Envelope.model_validate({**unsigned, "signature": None})
    raw_sig = crypto.sign_bytes(private_key, env.canonical_bytes())
    return {
        **env.unsigned_dict(),
        "signature": base64.b64encode(raw_sig).decode("ascii"),
    }


def verify_envelope_signature(
    envelope: dict[str, Any], public_key_b64: str
) -> bool:
    """Verify an envelope's signature. Never raises; False on any fault."""
    from app.identity import crypto

    try:
        signature_b64 = envelope.get("signature")
        if not signature_b64 or not public_key_b64:
            return False
        public_key = crypto.load_public_key(
            base64.b64decode(public_key_b64.encode("ascii"), validate=True)
        )
        signature = base64.b64decode(
            signature_b64.encode("ascii"), validate=True
        )
        env = Envelope.model_validate(
            {k: v for k, v in envelope.items() if k != "signature"}
        )
        return crypto.verify_bytes(public_key, env.canonical_bytes(), signature)
    except Exception:
        return False


def build_signed_error(
    private_key,
    *,
    sender: str,
    recipient: str,
    correlation_id: str,
    code: str,
    message: str,
) -> dict[str, Any]:
    """A signed ``error`` envelope (unknown types, policy denials, ...)."""
    now = utc_now_iso()
    return sign_envelope(
        private_key,
        {
            "protocol": PROTOCOL,
            "version": VERSION,
            "message_id": f"msg_{uuid.uuid4().hex}",
            "correlation_id": correlation_id,
            "sender": sender,
            "recipient": recipient,
            "timestamp": now,
            "expires_at": utc_iso_in(ERROR_TTL_SECONDS),
            "message_type": "error",
            "payload": {"code": code, "message": message},
        },
    )


__all__ = [
    "ERROR_TTL_SECONDS",
    "MESSAGE_TYPES",
    "PROTOCOL",
    "VERSION",
    "CanonicalizationError",
    "Envelope",
    "EnvelopeError",
    "build_signed_error",
    "canonical_json_bytes",
    "parse_iso",
    "sign_envelope",
    "utc_iso_in",
    "utc_now_iso",
    "verify_envelope_signature",
]
