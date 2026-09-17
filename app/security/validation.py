"""
Structural validation for A2A envelopes.

The gateway validates the structure of envelopes, not the signatures
(which are verified by the destination agent).
"""
from __future__ import annotations

import re
from typing import Any

AGENT_ID_PATTERN = re.compile(r"^nexus:ed25519:[0-9a-f]{32}$")
TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
VALID_MESSAGE_TYPES = {
    # 0.1 vocabulary
    "request",
    "response",
    "task_request",
    "task_response",
    "task_proposal",
    # 0.2 vocabulary (M6)
    "error",
    "task_progress",
    "task_cancel",
    "task_cancelled",
    "capability_query",
    "capability_response",
    "approval_required",
    "approval_granted",
    "approval_denied",
}
#: Protocol versions this gateway forwards. The gateway is a relay and does not
#: interpret envelopes, so it accepts every version the app understands rather
#: than pinning one - otherwise a 0.1 peer's message would be refused by the
#: relay the moment the app started sending 0.2.
SUPPORTED_PROTOCOL_VERSIONS = {"0.1", "0.2"}

def validate_envelope_structure(envelope: dict[str, Any]) -> tuple[bool, str | None]:
    """
    Validate that an envelope dictionary has the required fields with correct types.
    """
    if not isinstance(envelope, dict):
        return False, "Envelope must be a dictionary"

    if envelope.get("protocol") != "nexus-a2a":
        return False, "Invalid or missing protocol"

    if envelope.get("version") not in SUPPORTED_PROTOCOL_VERSIONS:
        return False, "Invalid or missing version"

    sender = envelope.get("sender")
    if not isinstance(sender, str) or not AGENT_ID_PATTERN.match(sender):
        return False, "Invalid or missing sender ID"

    recipient = envelope.get("recipient")
    if not isinstance(recipient, str) or not AGENT_ID_PATTERN.match(recipient):
        return False, "Invalid or missing recipient ID"

    message_id = envelope.get("message_id")
    if not isinstance(message_id, str) or not message_id:
        return False, "Invalid or missing message_id"

    task_id = envelope.get("task_id")
    if not isinstance(task_id, str) or not task_id:
        return False, "Invalid or missing task_id"

    timestamp = envelope.get("timestamp")
    if not isinstance(timestamp, str) or not TIMESTAMP_PATTERN.match(timestamp):
        return False, "Invalid or missing timestamp"

    expires_at = envelope.get("expires_at")
    if not isinstance(expires_at, str) or not TIMESTAMP_PATTERN.match(expires_at):
        return False, "Invalid or missing expires_at"

    message_type = envelope.get("message_type")
    if not isinstance(message_type, str) or message_type not in VALID_MESSAGE_TYPES:
        return False, f"Invalid or missing message_type"

    purpose = envelope.get("purpose")
    if not isinstance(purpose, str) or not purpose:
        return False, "Invalid or missing purpose"

    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        return False, "Invalid or missing payload"

    signature = envelope.get("signature")
    if signature is not None and not isinstance(signature, str):
        return False, "Signature must be a string if present"

    return True, None

def validate_relay_sender(envelope: dict[str, Any], authenticated_agent_id: str) -> tuple[bool, str | None]:
    """
    Verify that the envelope's sender matches the authenticated connection's agent_id.
    """
    sender = envelope.get("sender")
    if sender != authenticated_agent_id:
        return False, f"Sender ID '{sender}' does not match authenticated agent ID '{authenticated_agent_id}'"
    return True, None
