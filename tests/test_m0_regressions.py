"""M0 regression tests for the Nexus Gateway.

Covers:
    H3  handle ownership could be reassigned (or raise an opaque
        IntegrityError) because the upsert conflicted on agent_id while
        handle carried a full unique constraint
    M5  the schema was created with create_all() at startup despite
        shipping an Alembic migration, so migrations never expressed
        alterations and could not be exercised by tests
    L1  a redundant ``except (..., Exception)`` tuple in signature verification
"""

from __future__ import annotations

import base64
import inspect
import uuid

import pytest

from app.security.crypto import (
    Ed25519PublicKey,
    agent_id_from_public_key_bytes,
    verify_signature,
)
from app.storage.models import HANDLE_UNIQUE_INDEX, RegisteredAgent
from app.storage.repository import GatewayRepository, HandleConflictError


def _make_agent(tag: str = "") -> dict:
    """Create an agent identity dict with a real Ed25519 keypair."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )

    priv = Ed25519PrivateKey.generate()
    raw = priv.public_key().public_bytes(
        encoding=Encoding.Raw, format=PublicFormat.Raw
    )
    return {
        "priv": priv,
        "raw": raw,
        "key_b64": base64.b64encode(raw).decode("ascii"),
        "agent_id": agent_id_from_public_key_bytes(raw),
        "display_name": f"Agent {tag or uuid.uuid4().hex[:6]}",
    }


def _handle(prefix: str) -> str:
    """Unique handle so tests never collide across runs."""
    return f"{prefix}{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------------------
# H3: handle ownership is atomic and non-transferable
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_handle_claimed_then_protected_from_other_agent(repository):
    """A handle claimed by one agent cannot be taken by a different agent."""
    alice = _make_agent("alice")
    bob = _make_agent("bob")
    handle = _handle("shared")

    created = await repository.register_agent(
        agent_id=alice["agent_id"],
        public_key=alice["key_b64"],
        display_name=alice["display_name"],
        handle=handle,
        agent_card=None,
    )
    assert created.handle == handle

    # A DIFFERENT agent asking for the same handle must be refused.
    with pytest.raises(HandleConflictError) as exc:
        await repository.register_agent(
            agent_id=bob["agent_id"],
            public_key=bob["key_b64"],
            display_name=bob["display_name"],
            handle=handle,
            agent_card=None,
        )
    assert exc.value.handle == handle

    # Alice still owns it, and Bob was not created at all.
    still = await repository.get_by_handle(handle)
    assert still is not None
    assert still.agent_id == alice["agent_id"]
    assert await repository.get_agent(bob["agent_id"]) is None


@pytest.mark.asyncio
async def test_reconnect_by_same_agent_keeps_handle(repository):
    """An agent may reconnect repeatedly with its own handle."""
    alice = _make_agent("alice")
    handle = _handle("alice")

    for _ in range(3):
        record = await repository.register_agent(
            agent_id=alice["agent_id"],
            public_key=alice["key_b64"],
            display_name=alice["display_name"],
            handle=handle,
            agent_card=None,
        )
        assert record.handle == handle
        assert record.agent_id == alice["agent_id"]


@pytest.mark.asyncio
async def test_multiple_agents_without_handles_coexist(repository):
    """NULL handles must not collide (partial index covers non-NULL only).

    NOTE: register_agent derives a handle from display_name when none is
    given, so a NULL handle requires display_name to be None as well.
    """
    created = []
    for _ in range(3):
        ident = _make_agent()
        record = await repository.register_agent(
            agent_id=ident["agent_id"],
            public_key=ident["key_b64"],
            display_name=None,
            handle=None,
            agent_card=None,
        )
        created.append(record)

    assert len(created) == 3
    assert all(r.handle is None for r in created)


@pytest.mark.asyncio
async def test_agent_can_claim_a_new_handle_when_it_has_none(repository):
    """An agent registered without a handle may claim one later."""
    alice = _make_agent("alice")
    await repository.register_agent(
        agent_id=alice["agent_id"],
        public_key=alice["key_b64"],
        display_name=None,
        handle=None,
        agent_card=None,
    )
    assert (await repository.get_agent(alice["agent_id"])).handle is None

    handle = _handle("later")
    record = await repository.register_agent(
        agent_id=alice["agent_id"],
        public_key=alice["key_b64"],
        display_name=alice["display_name"],
        handle=handle,
        agent_card=None,
    )
    assert record.handle == handle


@pytest.mark.asyncio
async def test_handle_conflict_does_not_destroy_existing_card(repository):
    """A rejected claim must leave the incumbent's record untouched."""
    alice = _make_agent("alice")
    bob = _make_agent("bob")
    handle = _handle("keep")
    card = {"agent_id": alice["agent_id"], "display_name": "Alice", "signature": "x"}

    await repository.register_agent(
        agent_id=alice["agent_id"],
        public_key=alice["key_b64"],
        display_name=alice["display_name"],
        handle=handle,
        agent_card=card,
    )

    with pytest.raises(HandleConflictError):
        await repository.register_agent(
            agent_id=bob["agent_id"],
            public_key=bob["key_b64"],
            display_name=bob["display_name"],
            handle=handle,
            agent_card={"agent_id": bob["agent_id"]},
        )

    incumbent = await repository.get_agent(alice["agent_id"])
    assert incumbent.handle == handle
    assert incumbent.agent_card == card
    assert incumbent.public_key == alice["key_b64"]


@pytest.mark.asyncio
async def test_presence_tracker_propagates_handle_conflict(
    presence_tracker, repository
):
    """The connection path must surface the conflict, not swallow it."""
    alice = _make_agent("alice")
    bob = _make_agent("bob")
    handle = _handle("presence")

    await presence_tracker.agent_came_online(
        agent_id=alice["agent_id"],
        public_key=alice["key_b64"],
        display_name=alice["display_name"],
        handle=handle,
        agent_card=None,
    )

    with pytest.raises(HandleConflictError):
        await presence_tracker.agent_came_online(
            agent_id=bob["agent_id"],
            public_key=bob["key_b64"],
            display_name=bob["display_name"],
            handle=handle,
            agent_card=None,
        )


def test_handle_uniqueness_is_a_partial_index():
    """Handle uniqueness must be a PARTIAL index so ON CONFLICT can arbitrate.

    A full unique constraint cannot be used as a conflict target for an insert
    that also collides on the agent_id primary key - which is why handle
    claims were not atomic.
    """
    indexes = {i.name: i for i in RegisteredAgent.__table__.indexes}
    assert HANDLE_UNIQUE_INDEX in indexes
    idx = indexes[HANDLE_UNIQUE_INDEX]
    assert idx.unique is True
    assert idx.dialect_options["postgresql"].get("where") is not None, (
        "handle unique index must be partial (WHERE handle IS NOT NULL)"
    )
    # No remaining full unique constraint on handle.
    for constraint in RegisteredAgent.__table__.constraints:
        cols = getattr(constraint, "columns", None)
        if cols is not None and [c.name for c in cols] == ["handle"]:
            pytest.fail(f"stale UNIQUE constraint on handle: {constraint}")


# ---------------------------------------------------------------------------
# M5: schema is owned by migrations, not create_all()
# ---------------------------------------------------------------------------


def _code_only(obj: object) -> str:
    """Source of ``obj`` with comments and docstrings stripped.

    Static assertions must not match explanatory comments (they did once).
    """
    import io
    import tokenize

    src = inspect.getsource(obj)
    out: list[str] = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if tok.type == tokenize.COMMENT:
                continue
            if tok.type == tokenize.STRING and tok.line.strip().startswith(
                ('"""', "'''")
            ):
                continue
            out.append(tok.string)
    except tokenize.TokenError:  # pragma: no cover
        return src
    return "\n".join(out)


def test_gateway_startup_does_not_create_tables_directly():
    """create_all() must not be the schema authority in the app path."""
    import app.main as gateway_main

    src = _code_only(gateway_main)
    assert "create_all" not in src, (
        "gateway startup must delegate schema creation to app/storage/schema.py"
    )
    assert "ensure_schema" in src


@pytest.mark.asyncio
async def test_schema_verify_mode_accepts_existing_schema(db_engine):
    """ensure_schema(verify) must pass when the schema is present."""
    from app.storage.schema import ensure_schema

    await ensure_schema(
        db_engine,
        mode="verify",
        database_url="postgresql+asyncpg://unused/unused",
    )


@pytest.mark.asyncio
async def test_schema_rejects_unknown_mode(db_engine):
    from app.storage.schema import SchemaError, ensure_schema

    with pytest.raises(SchemaError):
        await ensure_schema(
            db_engine, mode="nonsense", database_url="postgresql+asyncpg://u/u"
        )


# ---------------------------------------------------------------------------
# L1: signature verification boundary
# ---------------------------------------------------------------------------


def test_verify_signature_handles_malformed_input_without_raising():
    """Malformed keys/signatures return False and never propagate."""
    agent = _make_agent()
    sig = agent["priv"].sign(b"hello")
    sig_b64 = base64.b64encode(sig).decode("ascii")

    # Correct signature verifies.
    assert verify_signature(agent["key_b64"], b"hello", sig_b64) is True
    # Wrong data fails.
    assert verify_signature(agent["key_b64"], b"other", sig_b64) is False
    # Wrong key length fails.
    assert verify_signature(base64.b64encode(b"short").decode(), b"hello", sig_b64) is False
    # Wrong signature length fails.
    assert verify_signature(agent["key_b64"], b"hello", base64.b64encode(b"x").decode()) is False
    # Non-base64 input fails without raising.
    assert verify_signature("!!!not-base64!!!", b"hello", sig_b64) is False
    assert verify_signature(agent["key_b64"], b"hello", "!!!not-base64!!!") is False
    # Empty input fails.
    assert verify_signature("", b"hello", sig_b64) is False


def test_signature_verification_has_no_redundant_exception_tuple():
    """The `except (..., Exception)` tuple was redundant and lint-invalid."""
    from app.security import crypto as gw_crypto

    src = _code_only(gw_crypto.verify_signature)
    assert "InvalidSignature, Exception)" not in src
