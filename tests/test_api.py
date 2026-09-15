"""Tests for Gateway REST endpoints (health and agents listing)."""

from __future__ import annotations

import httpx
import pytest
from httpx import ASGITransport

from app.main import app
from app.storage.repository import GatewayRepository
from tests.conftest import TestAgentIdentity


@pytest.mark.asyncio
async def test_health_endpoint() -> None:
    """GET /health returns healthy status and service version."""
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["service"] == "nexus-gateway"
        assert "port" in data
        assert "connections" in data


@pytest.mark.asyncio
async def test_agents_endpoint(
    agent_alice: TestAgentIdentity,
    repository: GatewayRepository,
) -> None:
    """GET /agents lists online agents without exposing private keys or sensitive state."""
    # Register an agent as online in DB
    await repository.register_agent(
        agent_id=agent_alice.agent_id,
        public_key=agent_alice.public_key_b64,
        display_name="Alice Assistant",
    )
    await repository.set_online(agent_alice.agent_id, online=True)

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/agents")
        assert resp.status_code == 200
        data = resp.json()
        assert "agents" in data
        assert "total" in data
