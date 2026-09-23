"""V2 relay queue tests (TDD red first, PG-gated).

Offline persist, reconnect redelivery, ack settles, TTL expiry, DLQ
after N attempts, UNIQUE(message_id) dedup (no memory sets), per-recipient
cap with oldest-to-DLQ, and SKIP LOCKED concurrent claims.
"""

from __future__ import annotations

import asyncio

from tests.relay_db import make_envelope, new_agent, run

GOOD_EXP = "2027-09-20T12:00:00Z"


def _enqueue_signed(session_factory, envelope, **kw):
    async def main():
        from relay import queue

        async with session_factory() as s:
            status = await queue.enqueue(s, envelope=envelope, **kw)
            await s.commit()
            return status

    return run(main())


def test_offline_persist_and_redeliver_on_reconnect(relay_engine):
    from relay import queue
    from relay.db import make_session_factory

    _, _, alice = new_agent()
    _, _, bob = new_agent()
    Session = make_session_factory(relay_engine)
    env = make_envelope(
        sender=alice, recipient=bob, message_id="msg_offline001",
        expires_at=GOOD_EXP,
    )

    async def main():
        async with Session() as s:
            assert await queue.enqueue(s, envelope=env) == "queued"
            await s.commit()
        # Bob "reconnects": pending claim returns the stored message.
        async with Session() as s:
            rows = await queue.claim_for_recipient(s, bob, limit=10)
            await s.commit()
            return rows

    rows = run(main())
    assert [r["message_id"] for r in rows] == ["msg_offline001"]
    assert rows[0]["envelope"]["sender"] == alice


def test_ack_settles_message(relay_engine):
    from relay import queue
    from relay.db import make_session_factory

    _, _, alice = new_agent()
    _, _, bob = new_agent()
    Session = make_session_factory(relay_engine)
    env = make_envelope(
        sender=alice, recipient=bob, message_id="msg_ack001",
        expires_at=GOOD_EXP,
    )

    async def main():
        async with Session() as s:
            await queue.enqueue(s, envelope=env)
            await s.commit()
        async with Session() as s:
            assert await queue.ack_delivered(s, "msg_ack001") is True
            await s.commit()
        async with Session() as s:
            rows = await queue.claim_for_recipient(s, bob, limit=10)
            depth = await queue.queue_depth(s, bob)
            return rows, depth

    rows, depth = run(main())
    assert rows == []
    assert depth == 0


def test_same_message_id_twice_is_one_delivery(relay_engine):
    from relay import queue
    from relay.db import make_session_factory

    _, _, alice = new_agent()
    _, _, bob = new_agent()
    Session = make_session_factory(relay_engine)
    env = make_envelope(
        sender=alice, recipient=bob, message_id="msg_dedup001",
        expires_at=GOOD_EXP,
    )

    async def main():
        async with Session() as s:
            first = await queue.enqueue(s, envelope=env)
            second = await queue.enqueue(s, envelope=dict(env))
            await s.commit()
            rows = await queue.claim_for_recipient(s, bob, limit=10)
            await s.commit()
            return first, second, rows

    first, second, rows = run(main())
    assert first == "queued"
    assert second == "dedup_hit"
    assert [r["message_id"] for r in rows] == ["msg_dedup001"]


def test_ttl_expiry_sweeps_and_never_delivers(relay_engine):
    from relay import queue
    from relay.db import make_session_factory

    _, _, alice = new_agent()
    _, _, bob = new_agent()
    Session = make_session_factory(relay_engine)
    env = make_envelope(
        sender=alice, recipient=bob, message_id="msg_ttl001",
        timestamp="2026-09-20T12:00:00Z",
        expires_at="2026-09-20T12:01:00Z",  # long past
    )

    async def main():
        async with Session() as s:
            await queue.enqueue(s, envelope=env)
            await s.commit()
        async with Session() as s:
            swept = await queue.sweep_expired(s)
            await s.commit()
        async with Session() as s:
            rows = await queue.claim_for_recipient(s, bob, limit=10)
            return swept, rows

    swept, rows = run(main())
    assert swept == 1
    assert rows == []


def test_dlq_after_n_attempts(relay_engine):
    from relay import queue
    from relay.db import make_session_factory

    _, _, alice = new_agent()
    _, _, bob = new_agent()
    Session = make_session_factory(relay_engine)
    env = make_envelope(
        sender=alice, recipient=bob, message_id="msg_dlq001",
        expires_at=GOOD_EXP,
    )

    async def main():
        async with Session() as s:
            await queue.enqueue(s, envelope=env)
            await s.commit()
        # Two claims (attempts 1, 2); the third claim moves it to DLQ.
        for _ in range(2):
            async with Session() as s:
                rows = await queue.claim_for_recipient(
                    s, bob, limit=10, max_attempts=2
                )
                await s.commit()
                assert len(rows) == 1
        async with Session() as s:
            rows = await queue.claim_for_recipient(
                s, bob, limit=10, max_attempts=2
            )
            dlq = await queue.dlq_depth(s, bob)
            await s.commit()
            return rows, dlq

    rows, dlq = run(main())
    assert rows == []
    assert dlq == 1


def test_full_queue_moves_oldest_to_dlq(relay_engine):
    from relay import queue
    from relay.db import make_session_factory

    _, _, alice = new_agent()
    _, _, bob = new_agent()
    Session = make_session_factory(relay_engine)

    async def main():
        async with Session() as s:
            for i in range(3):
                await queue.enqueue(
                    s,
                    envelope=make_envelope(
                        sender=alice, recipient=bob,
                        message_id=f"msg_cap00{i}",
                        expires_at=GOOD_EXP,
                    ),
                    max_per_recipient=2,
                )
            await s.commit()
        async with Session() as s:
            rows = await queue.claim_for_recipient(s, bob, limit=10)
            dlq = await queue.dlq_depth(s, bob)
            return [r["message_id"] for r in rows], dlq

    ids, dlq = run(main())
    assert ids == ["msg_cap001", "msg_cap002"]  # oldest evicted
    assert dlq == 1


def test_concurrent_claims_never_double_deliver(relay_engine):
    from relay import queue
    from relay.db import make_session_factory

    _, _, alice = new_agent()
    _, _, bob = new_agent()
    Session = make_session_factory(relay_engine)

    async def main():
        async with Session() as s:
            for i in range(4):
                await queue.enqueue(
                    s,
                    envelope=make_envelope(
                        sender=alice, recipient=bob,
                        message_id=f"msg_race00{i}",
                        expires_at=GOOD_EXP,
                    ),
                )
            await s.commit()

        # Warm the pool so both claims hold a live connection: the test
        # is about SKIP LOCKED partitioning, not pool ramp-up timing.
        async def ping():
            from sqlalchemy import text

            async with Session() as s:
                await s.execute(text("SELECT 1"))

        await asyncio.gather(ping(), ping())

        async def claim():
            async with Session() as s:
                rows = await queue.claim_for_recipient(s, bob, limit=10)
                await s.commit()
                return [r["message_id"] for r in rows]

        a, b = await asyncio.gather(claim(), claim())
        return a, b

    a, b = run(main())
    assert sorted(a + b) == [f"msg_race00{i}" for i in range(4)]
    assert set(a).isdisjoint(set(b))
