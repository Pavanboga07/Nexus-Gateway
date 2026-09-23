"""V2 relay auth tests (TDD red first).

Challenge-response: 32-byte challenges signed locally; the server
verifies the agent_id<->key binding AND the signature. Challenges are
single-use (replay rejected) and short-lived. Challenge state lives in
Postgres (shared-state-in-DB), so replay tests need PG and skip without
it; pure byte-shape tests always run.
"""

from __future__ import annotations

import base64

from tests.relay_db import new_agent, run


def test_challenge_is_32_bytes_and_unique():
    from relay.auth import new_challenge_bytes

    c1, c2 = new_challenge_bytes(), new_challenge_bytes()
    assert len(c1) == 32
    assert len(c2) == 32
    assert c1 != c2


def test_challenge_base64_round_trip():
    from relay.auth import decode_challenge, encode_challenge, new_challenge_bytes

    raw = new_challenge_bytes()
    assert decode_challenge(encode_challenge(raw)) == raw


def test_auth_round_trip_ok(relay_engine):
    from relay import auth
    from relay.db import make_session_factory
    from app.identity import crypto

    priv, pub_b64, agent_id = new_agent()

    async def main():
        Session = make_session_factory(relay_engine)
        async with Session() as s:
            challenge_b64 = await auth.mint_challenge(s)
            await s.commit()
            raw = base64.b64decode(challenge_b64.encode("ascii"))
            sig = crypto.sign_bytes(priv, raw)
            sig_b64 = base64.b64encode(sig).decode("ascii")
            async with Session() as s2:
                found = await auth.verify_and_consume(
                    s2,
                    challenge_b64=challenge_b64,
                    agent_id=agent_id,
                    public_key_b64=pub_b64,
                    signature_b64=sig_b64,
                )
                await s2.commit()
                return found

    assert run(main()) == agent_id


def test_wrong_key_signature_rejected(relay_engine):
    from relay import auth
    from relay.db import make_session_factory
    from app.identity import crypto

    priv_a, pub_b64_a, agent_id_a = new_agent()
    _, pub_b64_b, _ = new_agent()

    async def main():
        Session = make_session_factory(relay_engine)
        async with Session() as s:
            challenge_b64 = await auth.mint_challenge(s)
            await s.commit()
            # Attacker signs with A's key but claims B's binding... in any
            # mismatch combination verification must fail.
            raw = base64.b64decode(challenge_b64.encode("ascii"))
            from relay.auth import AuthError

            other_priv, _, _ = new_agent()
            bad_sig = base64.b64encode(
                crypto.sign_bytes(other_priv, raw)
            ).decode("ascii")
            async with Session() as s2:
                try:
                    await auth.verify_and_consume(
                        s2,
                        challenge_b64=challenge_b64,
                        agent_id=agent_id_a,
                        public_key_b64=pub_b64_a,
                        signature_b64=bad_sig,
                    )
                    return "accepted"
                except AuthError as exc:
                    return exc.code

    assert run(main()) == "INVALID_SIGNATURE"


def test_agent_id_key_mismatch_rejected(relay_engine):
    from relay import auth
    from relay.auth import AuthError
    from relay.db import make_session_factory
    from app.identity import crypto

    priv, pub_b64, agent_id = new_agent()
    _, other_pub_b64, _ = new_agent()

    async def main():
        Session = make_session_factory(relay_engine)
        async with Session() as s:
            challenge_b64 = await auth.mint_challenge(s)
            await s.commit()
            raw = base64.b64decode(challenge_b64.encode("ascii"))
            sig_b64 = base64.b64encode(
                crypto.sign_bytes(priv, raw)
            ).decode("ascii")
            async with Session() as s2:
                try:
                    await auth.verify_and_consume(
                        s2,
                        challenge_b64=challenge_b64,
                        agent_id=agent_id,  # A's id...
                        public_key_b64=other_pub_b64,  # ...with B's key
                        signature_b64=sig_b64,
                    )
                    return "accepted"
                except AuthError as exc:
                    return exc.code

    assert run(main()) == "IDENTITY_MISMATCH"


def test_replayed_challenge_rejected(relay_engine):
    from relay import auth
    from relay.auth import AuthError
    from relay.db import make_session_factory
    from app.identity import crypto

    priv, pub_b64, agent_id = new_agent()

    async def main():
        Session = make_session_factory(relay_engine)
        async with Session() as s:
            challenge_b64 = await auth.mint_challenge(s)
            await s.commit()
            raw = base64.b64decode(challenge_b64.encode("ascii"))
            sig_b64 = base64.b64encode(
                crypto.sign_bytes(priv, raw)
            ).decode("ascii")
            async with Session() as s2:
                await auth.verify_and_consume(
                    s2,
                    challenge_b64=challenge_b64,
                    agent_id=agent_id,
                    public_key_b64=pub_b64,
                    signature_b64=sig_b64,
                )
                await s2.commit()
            async with Session() as s3:
                try:
                    await auth.verify_and_consume(
                        s3,
                        challenge_b64=challenge_b64,
                        agent_id=agent_id,
                        public_key_b64=pub_b64,
                        signature_b64=sig_b64,
                    )
                    return "accepted"
                except AuthError as exc:
                    return exc.code

    assert run(main()) == "REPLAY"


def test_unknown_challenge_rejected(relay_engine):
    from relay import auth
    from relay.auth import AuthError, encode_challenge, new_challenge_bytes
    from relay.db import make_session_factory

    _, pub_b64, agent_id = new_agent()

    async def main():
        Session = make_session_factory(relay_engine)
        async with Session() as s:
            try:
                await auth.verify_and_consume(
                    s,
                    challenge_b64=encode_challenge(new_challenge_bytes()),
                    agent_id=agent_id,
                    public_key_b64=pub_b64,
                    signature_b64="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
                )
                return "accepted"
            except AuthError as exc:
                return exc.code

    assert run(main()) == "INVALID_CHALLENGE"
