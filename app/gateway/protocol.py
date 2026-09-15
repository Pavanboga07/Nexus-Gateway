from __future__ import annotations

from enum import Enum

GATEWAY_PROTOCOL = 'nexus-gw'
GATEWAY_VERSION = '0.1'
MAX_FRAME_SIZE = 65536

AUTH_CHALLENGE = 'auth_challenge'
AUTH_RESULT = 'auth_result'
DELIVERY = 'delivery'
DELIVERY_FAILED = 'delivery_failed'
PRESENCE_RESULT = 'presence_result'
ERROR = 'error'

AUTH_RESPONSE = 'auth_response'
RELAY_ENVELOPE = 'relay_envelope'
DELIVERY_ACK = 'delivery_ack'
PRESENCE_QUERY = 'presence_query'

HEARTBEAT = 'heartbeat'

class FrameType(str, Enum):
    AUTH_CHALLENGE = AUTH_CHALLENGE
    AUTH_RESULT = AUTH_RESULT
    DELIVERY = DELIVERY
    DELIVERY_FAILED = DELIVERY_FAILED
    PRESENCE_RESULT = PRESENCE_RESULT
    ERROR = ERROR
    
    AUTH_RESPONSE = AUTH_RESPONSE
    RELAY_ENVELOPE = RELAY_ENVELOPE
    DELIVERY_ACK = DELIVERY_ACK
    PRESENCE_QUERY = PRESENCE_QUERY
    
    HEARTBEAT = HEARTBEAT
