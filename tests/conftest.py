"""Test fixtures and cryptographic helpers for Nexus Gateway tests."""

from __future__ import annotations

import base64
import os
import uuid
from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.gateway.connection import ConnectionManager
from app.gateway.presence import PresenceTracker
from app.gateway.queue import OfflineQueue
from app.gateway.router import MessageRouter
from app.security.crypto import agent_id_from_public_key_bytes
from app.storage.models import Base
from app.storage.repository import GatewayRepository

TEST_DATABASE_URL = "postgresql+asyncpg://nexus:nexus@localhost:5433/nexus_gateway_test"


class TestAgentIdentity:
    """Helper representing an agent with Ed25519 signing capabilities for tests."""

    __test__ = False

    def __init__(self, display_name: str = "Test Agent") -> None:
        self.display_name = display_name
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key_raw = self.private_key.public_key().public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )
        self.public_key_b64 = base64.b64encode(self.public_key_raw).decode("ascii")
        self.agent_id = agent_id_from_public_key_bytes(self.public_key_raw)

    def sign(self, data: bytes) -> str:
        """Return base64-encoded signature over data."""
        raw_sig = self.private_key.sign(data)
        return base64.b64encode(raw_sig).decode("ascii")

    def make_auth_response(self, challenge_b64: str) -> dict:
        """Create an auth_response frame answering the given challenge."""
        challenge_bytes = base64.b64decode(challenge_b64.encode("ascii"))
        sig = self.sign(challenge_bytes)
        return {
            "type": "auth_response",
            "agent_id": self.agent_id,
            "public_key": self.public_key_b64,
            "signature": sig,
            "display_name": self.display_name,
        }

    def make_envelope(
        self,
        recipient_id: str,
        message_type: str = "request",
        purpose: str = "test",
        payload: dict | None = None,
    ) -> dict:
        """Create a valid A2A envelope structure signed by this agent."""
        now = datetime.now(timezone.utc)
        ts_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        exp_str = (now + timedelta(seconds=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
        env = {
            "protocol": "nexus-a2a",
            "version": "0.1",
            "message_id": f"msg_{uuid.uuid4().hex}",
            "task_id": f"task_{uuid.uuid4().hex}",
            "sender": self.agent_id,
            "recipient": recipient_id,
            "timestamp": ts_str,
            "expires_at": exp_str,
            "message_type": message_type,
            "purpose": purpose,
            "payload": payload or {"action": "test", "data_category": "test"},
        }
        # In real Nexus, envelope signing excludes signature.
        # Gateway doesn't verify envelope body signature, only structure.
        env["signature"] = self.sign(b"mock_canonical_bytes")
        return env


@pytest.fixture
def agent_alice() -> TestAgentIdentity:
    return TestAgentIdentity("Alice")


@pytest.fixture
def agent_bob() -> TestAgentIdentity:
    return TestAgentIdentity("Bob")


@pytest.fixture
def agent_charlie() -> TestAgentIdentity:
    return TestAgentIdentity("Charlie")


@pytest_asyncio.fixture
async def db_engine() -> AsyncIterator[AsyncEngine]:
    """Create test DB engine and tables, clean up after test."""
    try:
        engine = create_async_engine(TEST_DATABASE_URL, echo=False)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    except Exception as exc:
        pytest.skip(f"Test database unreachable: {exc}")

    yield engine

    async with engine.begin() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            await conn.execute(text(f'TRUNCATE TABLE "{table.name}" CASCADE;'))
    await engine.dispose()


@pytest_asyncio.fixture
async def session_factory(
    db_engine: AsyncEngine,
) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(
        db_engine, class_=AsyncSession, expire_on_commit=False
    )


@pytest_asyncio.fixture
async def repository(
    session_factory: async_sessionmaker[AsyncSession],
) -> GatewayRepository:
    return GatewayRepository(session_factory=session_factory)


@pytest.fixture
def connection_manager() -> ConnectionManager:
    return ConnectionManager(max_connections=50)


@pytest_asyncio.fixture
async def offline_queue(
    repository: GatewayRepository,
    connection_manager: ConnectionManager,
) -> OfflineQueue:
    return OfflineQueue(
        repository=repository,
        connection_manager=connection_manager,
    )


@pytest_asyncio.fixture
async def presence_tracker(
    connection_manager: ConnectionManager,
    repository: GatewayRepository,
) -> PresenceTracker:
    return PresenceTracker(
        connection_manager=connection_manager,
        repository=repository,
    )


@pytest_asyncio.fixture
async def message_router(
    connection_manager: ConnectionManager,
    offline_queue: OfflineQueue,
    repository: GatewayRepository,
) -> MessageRouter:
    return MessageRouter(
        connection_manager=connection_manager,
        queue=offline_queue,
        repository=repository,
    )
