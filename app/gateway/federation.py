"""Gateway federation: peer lookups across gateways (M9).

The problem
-----------
A gateway only knows the agents connected to *it*. There is no global
directory, so an agent registered on gateway B is invisible to an agent asking
gateway A. Before this module the only answer was "unknown", which makes a
multi-gateway network unusable.

What this does
--------------
**Read-only escalation.** When a local lookup misses, the gateway asks its
peers whether they know the agent, and returns their answer. That is what makes
discovery work across gateways.

What this deliberately does NOT do
-----------------------------------
**Message forwarding is not implemented.** A relay that accepts a message it
cannot deliver has to either store it indefinitely or drop it, and both are
worse than saying "I don't have that agent" so the sender can act. Silent
cross-gateway buffering would also mean two gateways both claiming delivery
responsibility for the same message, which is exactly the duplicate-delivery
ambiguity M2 removed.

So: discovery federates; delivery does not. An agent found on a peer gateway is
reachable by whatever transport the sender chooses, and a sender is never told
"accepted" for a message that is not accepted.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from app.config import get_settings

logger = logging.getLogger(__name__)


def peer_urls(raw: str | None) -> list[str]:
    """Parse the comma-separated peer list, normalised and de-duplicated."""
    if not raw:
        return []
    seen: list[str] = []
    for candidate in raw.split(","):
        url = candidate.strip().rstrip("/")
        if url and url not in seen:
            seen.append(url)
    return seen


class FederatedDirectory:
    """Queries peer gateways when a local lookup misses."""

    def __init__(
        self,
        *,
        peers: list[str] | None = None,
        enabled: bool | None = None,
        timeout_seconds: float | None = None,
    ) -> None:
        settings = get_settings()
        self._peers = peers if peers is not None else peer_urls(
            settings.gateway_peer_urls
        )
        self._enabled = (
            enabled
            if enabled is not None
            else settings.gateway_peer_lookup_enabled
        )
        self._timeout = (
            timeout_seconds
            if timeout_seconds is not None
            else settings.gateway_peer_timeout_seconds
        )

    @property
    def enabled(self) -> bool:
        return self._enabled and bool(self._peers)

    @property
    def peers(self) -> list[str]:
        return list(self._peers)

    async def lookup_agent(self, agent_id: str) -> dict[str, Any] | None:
        """Ask peers for one agent. Returns the first verified-looking answer.

        A peer's answer is treated as a HINT, not as truth: the caller (and
        ultimately the receiving agent) still verifies the agent's signed card
        before trusting it. A compromised peer can therefore misdirect a lookup
        but cannot forge an identity.
        """
        if not self.enabled:
            return None
        for peer in self._peers:
            payload = await self._get(f"{peer}/agents/{agent_id}")
            if payload:
                logger.info(
                    "peer_agent_found peer=%s agent_id=%s", peer, agent_id
                )
                return payload
        return None

    async def lookup_handle(self, handle: str) -> dict[str, Any] | None:
        """Ask peers for an agent by public handle."""
        if not self.enabled:
            return None
        clean = handle.lstrip("@")
        for peer in self._peers:
            payload = await self._get(f"{peer}/agents/handle/{clean}")
            if payload:
                logger.info("peer_handle_found peer=%s handle=%s", peer, clean)
                return payload
        return None

    async def search(self, query: str, *, limit: int = 10) -> list[dict[str, Any]]:
        """Search peers, returning combined results with their origin.

        ``source_gateway`` is included so a caller can see where an answer came
        from - an answer from a peer is a weaker claim than a local one, and the
        distinction should be visible rather than flattened.
        """
        if not self.enabled:
            return []
        results: list[dict[str, Any]] = []
        for peer in self._peers:
            payload = await self._get(f"{peer}/agents/search", params={"q": query})
            if not payload:
                continue
            for agent in payload.get("agents", [])[:limit]:
                results.append({**agent, "source_gateway": peer})
        return results[:limit]

    async def _get(
        self, url: str, *, params: dict[str, str] | None = None
    ) -> dict[str, Any] | None:
        """GET a peer endpoint, treating every failure as "no answer".

        A peer being down, slow, or returning garbage must not make the local
        gateway fail: a federation is a convenience, and one broken peer cannot
        be allowed to break the gateway's own directory.
        """
        try:
            async with httpx.AsyncClient(
                timeout=self._timeout, follow_redirects=False
            ) as client:
                response = await client.get(url, params=params)
            if response.status_code != 200:
                return None
            data = response.json()
            return data if isinstance(data, dict) else None
        except Exception as exc:  # noqa: BLE001
            logger.warning("peer_gateway_lookup_failed url=%s detail=%s", url, exc)
            return None


__all__ = ["FederatedDirectory", "peer_urls"]
