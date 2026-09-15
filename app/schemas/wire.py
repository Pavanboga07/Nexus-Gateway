from __future__ import annotations

from typing import Any, Literal, Optional
from pydantic import BaseModel, ConfigDict


class AuthChallenge(BaseModel):
    model_config = ConfigDict(extra='forbid')
    type: Literal['auth_challenge'] = 'auth_challenge'
    challenge: str
    protocol: str = 'nexus-gw'
    version: str = '0.1'


class AuthResult(BaseModel):
    model_config = ConfigDict(extra='forbid')
    type: Literal['auth_result'] = 'auth_result'
    success: bool
    agent_id: Optional[str] = None
    error: Optional[str] = None


class Delivery(BaseModel):
    model_config = ConfigDict(extra='forbid')
    type: Literal['delivery'] = 'delivery'
    relay_id: str
    envelope: dict[str, Any]


class DeliveryFailed(BaseModel):
    model_config = ConfigDict(extra='forbid')
    type: Literal['delivery_failed'] = 'delivery_failed'
    relay_id: str
    reason: str


class PresenceResult(BaseModel):
    model_config = ConfigDict(extra='forbid')
    type: Literal['presence_result'] = 'presence_result'
    agent_id: str
    online: bool
    last_seen: Optional[str] = None


class GatewayError(BaseModel):
    model_config = ConfigDict(extra='forbid')
    type: Literal['error'] = 'error'
    code: str
    message: str


class AuthResponse(BaseModel):
    model_config = ConfigDict(extra='forbid')
    type: Literal['auth_response'] = 'auth_response'
    agent_id: str
    public_key: str
    signature: str
    display_name: Optional[str] = None


class RelayEnvelope(BaseModel):
    model_config = ConfigDict(extra='forbid')
    type: Literal['relay_envelope'] = 'relay_envelope'
    relay_id: str
    recipient: str
    envelope: dict[str, Any]


class DeliveryAck(BaseModel):
    model_config = ConfigDict(extra='forbid')
    type: Literal['delivery_ack'] = 'delivery_ack'
    relay_id: str
    status: str = 'delivered'


class PresenceQuery(BaseModel):
    model_config = ConfigDict(extra='forbid')
    type: Literal['presence_query'] = 'presence_query'
    agent_id: str


class Heartbeat(BaseModel):
    model_config = ConfigDict(extra='forbid')
    type: Literal['heartbeat'] = 'heartbeat'
    timestamp: Optional[str] = None


def parse_client_frame(data: dict) -> AuthResponse | RelayEnvelope | DeliveryAck | PresenceQuery | Heartbeat:
    """Parse a client frame dictionary into the corresponding Pydantic model."""
    frame_type = data.get('type')
    if frame_type == 'auth_response':
        return AuthResponse.model_validate(data)
    elif frame_type == 'relay_envelope':
        return RelayEnvelope.model_validate(data)
    elif frame_type == 'delivery_ack':
        return DeliveryAck.model_validate(data)
    elif frame_type == 'presence_query':
        return PresenceQuery.model_validate(data)
    elif frame_type == 'heartbeat':
        return Heartbeat.model_validate(data)
    else:
        raise ValueError(f"Unknown client frame type: {frame_type}")


def parse_server_frame(data: dict) -> AuthChallenge | AuthResult | Delivery | DeliveryFailed | PresenceResult | GatewayError | Heartbeat:
    """Parse a server frame dictionary into the corresponding Pydantic model."""
    frame_type = data.get('type')
    if frame_type == 'auth_challenge':
        return AuthChallenge.model_validate(data)
    elif frame_type == 'auth_result':
        return AuthResult.model_validate(data)
    elif frame_type == 'delivery':
        return Delivery.model_validate(data)
    elif frame_type == 'delivery_failed':
        return DeliveryFailed.model_validate(data)
    elif frame_type == 'presence_result':
        return PresenceResult.model_validate(data)
    elif frame_type == 'error':
        return GatewayError.model_validate(data)
    elif frame_type == 'heartbeat':
        return Heartbeat.model_validate(data)
    else:
        raise ValueError(f"Unknown server frame type: {frame_type}")
