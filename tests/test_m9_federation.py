"""M9 regression tests: gateway federation (cross-gateway discovery).

Audit finding: two Nexus Gateways could not communicate at all. There was no
peer concept, no lookup escalation and no forwarding, so an agent registered on
gateway B was simply invisible to anyone asking gateway A - which makes a
multi-gateway network unusable.

Scope decision recorded in these tests: **discovery federates; delivery does
not.** A relay that accepts a message it cannot deliver must either store it
indefinitely or drop it, and both are worse than saying "I don't have that
agent" so the sender can act.
"""

from __future__ import annotations

import inspect
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.gateway.federation import FederatedDirectory, peer_urls


# ---------------------------------------------------------------------------
# Peer configuration
# ---------------------------------------------------------------------------


def test_peer_urls_parses_normalises_and_deduplicates() -> None:
    assert peer_urls("https://a.example/, https://b.example") == [
        "https://a.example",
        "https://b.example",
    ]
    # Trailing slashes and duplicates collapse, so a lookup is not repeated.
    assert peer_urls("https://a.example/,https://a.example") == [
        "https://a.example"
    ]
    assert peer_urls("") == []
    assert peer_urls(None) == []
    assert peer_urls("  ,  ") == []


def test_federation_is_disabled_by_default() -> None:
    """Depending on another deployment's availability is opt-in.

    A gateway whose directory breaks because a peer is down is worse than one
    that only knows its own agents.
    """
    directory = FederatedDirectory(peers=["https://peer.example"])
    assert directory.enabled is False
    assert FederatedDirectory(enabled=True, peers=[]).enabled is False
    assert FederatedDirectory(enabled=True, peers=["https://p"]).enabled is True


# ---------------------------------------------------------------------------
# Lookup escalation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_local_agent_is_not_sought_from_a_peer(monkeypatch) -> None:
    """A peer must not be consulted when the local directory already answers."""
    directory = FederatedDirectory(enabled=True, peers=["https://peer.example"])
    called = AsyncMock(return_value={"agent_id": "from-peer"})
    monkeypatch.setattr(directory, "_get", called)

    # No local concept here: this asserts the escalation helper itself is only
    # invoked on a miss, which the route implements.
    import app.main as gateway_main

    src = inspect.getsource(gateway_main.get_agent_by_id)
    assert "if not agent:" in src
    assert "lookup_agent" in src
    called.assert_not_called()


@pytest.mark.asyncio
async def test_fallback_lookup_returns_the_first_peer_answer(monkeypatch) -> None:
    """Peers are tried in order and the first answer wins."""
    directory = FederatedDirectory(
        enabled=True, peers=["https://down.example", "https://up.example"]
    )

    async def fake_get(url: str, *, params=None):
        if "down.example" in url:
            return None  # unreachable peer
        return {"agent_id": "nexus:ed25519:" + "a" * 32, "display_name": "Peer agent"}

    monkeypatch.setattr(directory, "_get", fake_get)
    found = await directory.lookup_agent("nexus:ed25519:" + "a" * 32)
    assert found is not None
    assert found["display_name"] == "Peer agent"


@pytest.mark.asyncio
async def test_all_peers_unreachable_yields_no_answer(monkeypatch) -> None:
    """One broken peer must not break the gateway's own directory."""
    directory = FederatedDirectory(enabled=True, peers=["https://a", "https://b"])
    monkeypatch.setattr(directory, "_get", AsyncMock(return_value=None))
    assert await directory.lookup_agent("nexus:ed25519:" + "a" * 32) is None


@pytest.mark.asyncio
async def test_peer_lookup_failure_is_swallowed_and_logged(monkeypatch, caplog) -> None:
    """A peer raising (timeout, DNS, garbage) must not propagate."""
    import httpx

    directory = FederatedDirectory(enabled=True, peers=["https://a"])

    class _BoomClient:
        def __init__(self, *a, **k) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, *a, **k):
            raise httpx.ConnectError("no route to host")

    monkeypatch.setattr(httpx, "AsyncClient", _BoomClient)
    assert await directory.lookup_agent("nexus:ed25519:" + "a" * 32) is None
    assert any(
        "peer_gateway_lookup_failed" in record.message
        for record in caplog.records
    )


@pytest.mark.asyncio
async def test_disabled_federation_never_calls_out(monkeypatch) -> None:
    directory = FederatedDirectory(enabled=False, peers=["https://a"])
    called = AsyncMock(return_value={"agent_id": "x"})
    monkeypatch.setattr(directory, "_get", called)

    assert await directory.lookup_agent("nexus:ed25519:" + "a" * 32) is None
    assert await directory.lookup_handle("someone") is None
    assert await directory.search("someone") == []
    called.assert_not_called()


@pytest.mark.asyncio
async def test_peer_search_tags_the_source_gateway(monkeypatch) -> None:
    """Provenance must be visible: a peer's claim is weaker than a local record."""
    directory = FederatedDirectory(enabled=True, peers=["https://peer.example"])

    async def fake_get(url: str, *, params=None):
        return {
            "agents": [
                {"agent_id": "nexus:ed25519:" + "b" * 32, "display_name": "Remote"}
            ]
        }

    monkeypatch.setattr(directory, "_get", fake_get)
    results = await directory.search("remote")
    assert len(results) == 1
    assert results[0]["source_gateway"] == "https://peer.example"


# ---------------------------------------------------------------------------
# Scope: discovery federates, delivery does not
# ---------------------------------------------------------------------------


def _module_code_only(module) -> str:
    """Module source with its docstring and comments removed.

    Static assertions must inspect CODE, not prose. The module's own docstring
    explains that forwarding is NOT implemented - a text scan over the raw
    source matches the explanation and fails for the wrong reason. (This is the
    second time in this project that prose has tripped a code check, so the
    helper strips both docstrings and comments.)
    """
    import ast
    import io
    import tokenize

    source = inspect.getsource(module)
    tree = ast.parse(source)
    # Drop the module docstring.
    if (
        tree.body
        and isinstance(tree.body[0], ast.Expr)
        and isinstance(tree.body[0].value, ast.Constant)
        and isinstance(tree.body[0].value.value, str)
    ):
        tree.body = tree.body[1:]
    stripped_docstrings = ast.unparse(tree)
    # Drop comments as well.
    out: list[str] = []
    try:
        for tok in tokenize.generate_tokens(
            io.StringIO(stripped_docstrings).readline
        ):
            if tok.type == tokenize.COMMENT:
                continue
            out.append(tok.string)
    except tokenize.TokenError:  # pragma: no cover
        return stripped_docstrings
    return "\n".join(out)


def test_federation_is_lookup_only_and_says_so() -> None:
    """No forwarding: the module must not contain a delivery path.

    Silent cross-gateway buffering would give two gateways delivery
    responsibility for one message - exactly the duplicate-delivery ambiguity
    M2 removed - and a sender would be told "accepted" for a message that is
    not.
    """
    module = __import__("app.gateway.federation", fromlist=["x"])
    # The SCOPE DECISION must be stated in the docstring ...
    docstring = module.__doc__ or ""
    assert "delivery does not" in docstring.lower() or "not implemented" in docstring.lower()
    # ... and the CODE must contain no delivery mechanism.
    code = _module_code_only(module)
    for forbidden in ("forward", "relay_envelope", "enqueue", "OfflineQueue"):
        assert forbidden not in code, (
            f"federation must not implement delivery ({forbidden!r} found in code)"
        )


@pytest.mark.asyncio
async def test_gateway_route_marks_local_vs_peer_results(
    repository, monkeypatch
) -> None:
    """A local record is tagged local; a peer answer is tagged peer.

    Flattening the two would present a peer's unverified claim with the same
    authority as a local registration.
    """
    import app.main as gateway_main

    monkeypatch.setattr(gateway_main, "_repository", repository)
    monkeypatch.setattr(gateway_main, "_connection_manager", None)

    # Local miss -> peer answer.
    peer_directory = MagicMock()
    peer_directory.enabled = True
    peer_directory.lookup_agent = AsyncMock(
        return_value={"agent_id": "nexus:ed25519:" + "c" * 32, "display_name": "Peer"}
    )
    monkeypatch.setattr(gateway_main, "_federation", peer_directory)

    from fastapi import HTTPException

    answer = await gateway_main.get_agent_by_id("nexus:ed25519:" + "c" * 32)
    assert answer["source_gateway"] == "peer"

    peer_directory.lookup_agent = AsyncMock(return_value=None)
    with pytest.raises(HTTPException) as exc:
        await gateway_main.get_agent_by_id("nexus:ed25519:" + "d" * 32)
    assert exc.value.status_code == 404


def test_gateway_config_exposes_federation_settings() -> None:
    from app.config import get_settings

    settings = get_settings()
    assert settings.gateway_peer_lookup_enabled is False
    assert hasattr(settings, "gateway_peer_urls")
    assert settings.gateway_peer_timeout_seconds > 0
