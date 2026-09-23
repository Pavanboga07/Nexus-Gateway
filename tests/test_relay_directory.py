"""V2 relay directory tests (TDD red first, PG-gated).

Authenticated writes (unsigned/forged cards -> 401 and never stored),
atomic handle claims (conflict -> clean 409 reject), unconditional
signature verification, pagination, per-IP rate limits, and no card
echo in write responses.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.relay_db import make_card, new_agent, run, sign_card_dict


def make_app(**kw):
    from relay.main import create_relay_app
    from tests.relay_db import TEST_URL

    return create_relay_app(database_url=TEST_URL, **kw)


def put_card(client, card):
    return client.put(f"/directory/{card['agent_id']}", json={"card": card})


def test_unauthenticated_write_rejected_and_nothing_stored(relay_engine):
    from relay.db import make_session_factory
    from relay.directory import get_entry

    priv, pub_b64, agent_id = new_agent()
    card = make_card(agent_id=agent_id, public_key=pub_b64)
    unsigned = dict(card)  # no signature at all

    with TestClient(make_app()) as client:
        resp = client.put(f"/directory/{agent_id}", json={"card": unsigned})
        assert resp.status_code == 401

        async def main():
            from tests.relay_db import TEST_URL
            from relay.db import make_engine

            engine = make_engine(TEST_URL)
            try:
                Session = make_session_factory(engine)
                async with Session() as s:
                    return await get_entry(s, agent_id)
            finally:
                await engine.dispose()

        assert run(main()) is None


def test_forged_card_never_stored(relay_engine):
    priv, pub_b64, agent_id = new_agent()
    other_priv, _, _ = new_agent()
    card = make_card(agent_id=agent_id, public_key=pub_b64)
    forged = sign_card_dict(other_priv, card)  # signed by the wrong key

    with TestClient(make_app()) as client:
        resp = put_card(client, forged)
        assert resp.status_code == 401
        assert client.get(f"/directory/{agent_id}").status_code == 404


def test_valid_write_then_read(relay_engine):
    priv, pub_b64, agent_id = new_agent()
    card = sign_card_dict(
        priv, make_card(agent_id=agent_id, public_key=pub_b64, handle="alice")
    )

    with TestClient(make_app()) as client:
        resp = put_card(client, card)
        assert resp.status_code == 200
        body = resp.json()
        assert body["agent_id"] == agent_id
        assert "card" not in body  # no card echo on write

        got = client.get(f"/directory/{agent_id}")
        assert got.status_code == 200
        assert got.json()["card"]["handle"] == "alice"


def test_handle_conflict_clean_reject(relay_engine):
    priv_a, pub_a, id_a = new_agent()
    priv_b, pub_b, id_b = new_agent()
    card_a = sign_card_dict(
        priv_a, make_card(agent_id=id_a, public_key=pub_a, handle="sam")
    )
    card_b = sign_card_dict(
        priv_b, make_card(agent_id=id_b, public_key=pub_b, handle="sam")
    )

    with TestClient(make_app()) as client:
        assert put_card(client, card_a).status_code == 200
        conflict = put_card(client, card_b)
        assert conflict.status_code == 409
        assert "handle" in conflict.json()["detail"].lower()
        # Loser's card is not stored under any identity.
        assert client.get(f"/directory/{id_b}").status_code == 404


def test_same_agent_may_reclaim_own_handle(relay_engine):
    priv, pub_b64, agent_id = new_agent()
    first = sign_card_dict(
        priv, make_card(agent_id=agent_id, public_key=pub_b64, handle="mo")
    )
    second = sign_card_dict(
        priv,
        make_card(
            agent_id=agent_id, public_key=pub_b64, handle="mo",
            display_name="Mo The Second",
        ),
    )

    with TestClient(make_app()) as client:
        assert put_card(client, first).status_code == 200
        assert put_card(client, second).status_code == 200
        got = client.get(f"/directory/{agent_id}")
        assert got.json()["card"]["display_name"] == "Mo The Second"


def test_directory_pagination(relay_engine):
    agents = []
    for handle in ("pag-a", "pag-b", "pag-c"):
        priv, pub_b64, agent_id = new_agent()
        agents.append(
            sign_card_dict(
                priv,
                make_card(
                    agent_id=agent_id, public_key=pub_b64, handle=handle,
                    display_name=f"Pager {handle}",
                ),
            )
        )

    with TestClient(make_app()) as client:
        for card in agents:
            assert put_card(client, card).status_code == 200
        page1 = client.get("/directory", params={"limit": 2, "offset": 0})
        assert page1.status_code == 200
        body1 = page1.json()
        assert body1["total"] >= 3
        assert len(body1["items"]) == 2
        page2 = client.get("/directory", params={"limit": 2, "offset": 2})
        assert len(page2.json()["items"]) >= 1
        ids1 = {i["agent_id"] for i in body1["items"]}
        ids2 = {i["agent_id"] for i in page2.json()["items"]}
        assert ids1.isdisjoint(ids2)


def test_directory_rate_limit(relay_engine):
    priv, pub_b64, agent_id = new_agent()

    with TestClient(make_app(directory_rate_limit=2)) as client:
        codes = []
        for _ in range(3):
            card = sign_card_dict(
                priv, make_card(agent_id=agent_id, public_key=pub_b64)
            )
            codes.append(put_card(client, card).status_code)
        assert codes[0] == 200
        assert codes[1] == 200
        assert codes[2] == 429
