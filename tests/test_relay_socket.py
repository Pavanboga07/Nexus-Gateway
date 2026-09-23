"""V2 relay socket tests (TDD red first, PG-gated).

Two-client delivery over real WebSockets (starlette TestClient, no
ports): handshake, live delivery + ack settle, kill-mid-flight
redelivery on reconnect, offline queue, heartbeats, close codes, and
the observability endpoints.
"""

from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.identity import crypto
from tests.relay_db import TEST_URL, make_envelope, new_agent, run


def make_app(**kw):
    from relay.main import create_relay_app

    kw.setdefault("ack_timeout", 1.0)
    return create_relay_app(database_url=TEST_URL, **kw)


def handshake(ws, priv, pub_b64, agent_id):
    frame = ws.receive_json()
    assert frame["type"] == "auth_challenge"
    raw = base64.b64decode(frame["challenge"].encode("ascii"))
    assert len(raw) == 32
    sig = base64.b64encode(crypto.sign_bytes(priv, raw)).decode("ascii")
    ws.send_json(
        {
            "type": "auth_response",
            "agent_id": agent_id,
            "public_key": pub_b64,
            "signature": sig,
            "correlation_id": frame.get("correlation_id"),
        }
    )
    result = ws.receive_json()
    assert result["type"] == "auth_result"
    return result


def authed_pair():
    """Two agents with keypairs; returns (a_priv, a_pub, a_id, b_*...)."""
    a_priv, a_pub, a_id = new_agent()
    b_priv, b_pub, b_id = new_agent()
    return a_priv, a_pub, a_id, b_priv, b_pub, b_id


def test_handshake_ok_and_no_card_echo(relay_engine):
    priv, pub_b64, agent_id = new_agent()
    with TestClient(make_app()) as client:
        with client.websocket_connect("/ws") as ws:
            result = handshake(ws, priv, pub_b64, agent_id)
            assert result["success"] is True
            assert result["agent_id"] == agent_id
            assert "agent_card" not in result
            assert "card" not in result


def test_wrong_key_auth_closes_4401(relay_engine):
    priv, pub_b64, agent_id = new_agent()
    _, other_pub, _ = new_agent()
    with TestClient(make_app()) as client:
        with pytest.raises(WebSocketDisconnect) as exc:
            with client.websocket_connect("/ws") as ws:
                frame = ws.receive_json()
                raw = base64.b64decode(frame["challenge"].encode("ascii"))
                sig = base64.b64encode(
                    crypto.sign_bytes(priv, raw)
                ).decode("ascii")
                # Right signature, wrong binding: A's sig, other key.
                ws.send_json(
                    {
                        "type": "auth_response",
                        "agent_id": agent_id,
                        "public_key": other_pub,
                        "signature": sig,
                    }
                )
                ws.receive_json()  # auth_result failure, then close
                ws.receive_json()  # raises WebSocketDisconnect
        assert exc.value.code == 4401


def test_unauthenticated_frame_closes_4401(relay_engine):
    _, _, alice = new_agent()
    _, _, bob = new_agent()
    with TestClient(make_app()) as client:
        with pytest.raises(WebSocketDisconnect) as exc:
            with client.websocket_connect("/ws") as ws:
                ws.receive_json()  # challenge, ignored
                ws.send_json(
                    {
                        "type": "relay_envelope",
                        "relay_id": "relay_sneaky001",
                        "recipient": bob,
                        "envelope": make_envelope(
                            sender=alice, recipient=bob
                        ),
                    }
                )
                ws.receive_json()
                ws.receive_json()
        assert exc.value.code == 4401


def test_live_delivery_and_ack_settles(relay_engine):
    a_priv, a_pub, a_id, b_priv, b_pub, b_id = authed_pair()
    env = make_envelope(
        sender=a_id, recipient=b_id, message_id="msg_live001",
        correlation_id="corr_live001",
        expires_at="2027-09-20T12:00:00Z",
    )
    with TestClient(make_app()) as client:
        with client.websocket_connect("/ws") as ws_b:
            assert handshake(ws_b, b_priv, b_pub, b_id)["success"] is True
            with client.websocket_connect("/ws") as ws_a:
                assert handshake(ws_a, a_priv, a_pub, a_id)["success"] is True
                ws_a.send_json(
                    {
                        "type": "relay_envelope",
                        "relay_id": "relay_live001",
                        "recipient": b_id,
                        "envelope": env,
                    }
                )
                delivery = ws_b.receive_json()
                assert delivery["type"] == "delivery"
                assert delivery["envelope"]["message_id"] == "msg_live001"
                ws_b.send_json(
                    {"type": "delivery_ack",
                     "relay_id": delivery["relay_id"]}
                )
                ack = ws_a.receive_json()
                assert ack["type"] == "delivery_ack"
                assert ack["relay_id"] == "relay_live001"
                assert ack["status"] == "delivered"

    async def main():
        from relay import queue
        from relay.db import make_engine, make_session_factory

        engine = make_engine(TEST_URL)
        try:
            Session = make_session_factory(engine)
            async with Session() as s:
                return await queue.queue_depth(s, b_id)
        finally:
            await engine.dispose()

    assert run(main()) == 0


def test_kill_mid_flight_redelivers_on_reconnect(relay_engine):
    a_priv, a_pub, a_id, b_priv, b_pub, b_id = authed_pair()
    env = make_envelope(
        sender=a_id, recipient=b_id, message_id="msg_redeliver001",
        expires_at="2027-09-20T12:00:00Z",
    )
    seen_ids: list[str] = []
    with TestClient(make_app()) as client:
        with client.websocket_connect("/ws") as ws_a:
            assert handshake(ws_a, a_priv, a_pub, a_id)["success"] is True
            with client.websocket_connect("/ws") as ws_b:
                assert handshake(ws_b, b_priv, b_pub, b_id)["success"] is True
                ws_a.send_json(
                    {
                        "type": "relay_envelope",
                        "relay_id": "relay_red001",
                        "recipient": b_id,
                        "envelope": env,
                    }
                )
                first = ws_b.receive_json()
                assert first["type"] == "delivery"
                seen_ids.append(first["envelope"]["message_id"])
            # ws_b drops WITHOUT ack (kill mid-flight); the sender gets
            # a queued ack after the ack timeout and the message stays.
            ack = ws_a.receive_json()
            assert ack["type"] == "delivery_ack"
            assert ack["status"] == "queued"
        # Bob reconnects: the unacked message is redelivered.
        with client.websocket_connect("/ws") as ws_b2:
            assert handshake(ws_b2, b_priv, b_pub, b_id)["success"] is True
            second = ws_b2.receive_json()
            assert second["type"] == "delivery"
            seen_ids.append(second["envelope"]["message_id"])
            ws_b2.send_json(
                {"type": "delivery_ack",
                 "relay_id": second["relay_id"]}
            )
    assert seen_ids == ["msg_redeliver001", "msg_redeliver001"]


def test_offline_message_queued_then_received(relay_engine):
    a_priv, a_pub, a_id, b_priv, b_pub, b_id = authed_pair()
    env = make_envelope(
        sender=a_id, recipient=b_id, message_id="msg_offline_ws001",
        expires_at="2027-09-20T12:00:00Z",
    )
    with TestClient(make_app()) as client:
        with client.websocket_connect("/ws") as ws_a:
            assert handshake(ws_a, a_priv, a_pub, a_id)["success"] is True
            ws_a.send_json(
                {
                    "type": "relay_envelope",
                    "relay_id": "relay_off001",
                    "recipient": b_id,
                    "envelope": env,
                }
            )
            ack = ws_a.receive_json()
            assert ack["status"] == "queued"
        with client.websocket_connect("/ws") as ws_b:
            assert handshake(ws_b, b_priv, b_pub, b_id)["success"] is True
            delivery = ws_b.receive_json()
            assert delivery["envelope"]["message_id"] == "msg_offline_ws001"
            ws_b.send_json(
                {"type": "delivery_ack",
                 "relay_id": delivery["relay_id"]}
            )


def test_heartbeat_updates_presence_and_observability(relay_engine):
    priv, pub_b64, agent_id = new_agent()
    with TestClient(make_app()) as client:
        assert client.get("/health").json() == {"status": "ok"}
        ready = client.get("/readyz")
        assert ready.status_code == 200
        assert ready.json()["ready"] is True
        with client.websocket_connect("/ws") as ws:
            assert handshake(ws, priv, pub_b64, agent_id)["success"] is True
            ws.send_json({"type": "heartbeat"})
            pong = ws.receive_json()
            assert pong["type"] == "heartbeat_ack"
        pres = client.get(f"/presence/{agent_id}")
        assert pres.status_code == 200
        assert pres.json()["agent_id"] == agent_id
        metrics = client.get("/metrics").json()
        for key in ("connections", "queue_depth", "deliveries",
                    "auth_failures"):
            assert key in metrics
