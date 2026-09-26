"""Unit tests for relay database URL handling (no DB, no network)."""

import pytest

from relay.db import normalize_database_url, resolve_database_url


def test_plain_postgres_url_upgraded_to_asyncpg():
    out = normalize_database_url(
        "postgresql://u:p@host/db?sslmode=require"
    )
    assert out == "postgresql+asyncpg://u:p@host/db?ssl=require"


def test_explicit_asyncpg_url_untouched():
    url = "postgresql+asyncpg://u:p@host/db?ssl=require"
    assert normalize_database_url(url) == url


def test_non_postgres_url_untouched():
    assert normalize_database_url("sqlite:///x.db") == "sqlite:///x.db"


def test_missing_url_raises(monkeypatch):
    monkeypatch.delenv("RELAY_DATABASE_URL", raising=False)
    with pytest.raises(RuntimeError):
        resolve_database_url(None)


def test_env_url_normalized(monkeypatch):
    monkeypatch.setenv(
        "RELAY_DATABASE_URL", "postgresql://u:p@host/db?sslmode=require"
    )
    assert (
        resolve_database_url(None)
        == "postgresql+asyncpg://u:p@host/db?ssl=require"
    )
