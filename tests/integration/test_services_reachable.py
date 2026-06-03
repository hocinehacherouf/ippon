"""Integration smoke tests — exercise the live infra dependencies.

These run against a real stack (compose locally, ``services:`` block in CI)
and verify the four storage / queue surfaces ippon depends on are reachable
and that schema migrations land cleanly. The full scan-chain end-to-end is
covered by ``just scan`` against a real repo, not by pytest.
"""

from __future__ import annotations

import httpx
import pytest
from sqlalchemy import text

from ippon.clickhouse import make_sync_client
from ippon.config import get_settings
from ippon.db import async_session_scope, make_async_engine, make_async_session_factory

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_postgres_reachable_and_schema_migrated() -> None:
    settings = get_settings()
    engine = make_async_engine(settings)
    factory = make_async_session_factory(engine)
    try:
        async with async_session_scope(factory) as session:
            # 1) basic SELECT
            row = (await session.execute(text("SELECT 1"))).scalar_one()
            assert row == 1
            # 2) alembic_version present (migrations applied)
            version = (
                await session.execute(text("SELECT version_num FROM alembic_version LIMIT 1"))
            ).scalar_one_or_none()
            assert version is not None, "alembic_version is empty — run `just migrate` first"
            # 3) one of our tables exists
            count = (await session.execute(text("SELECT count(*) FROM orgs"))).scalar_one()
            assert isinstance(count, int)
    finally:
        await engine.dispose()


def test_clickhouse_reachable_and_schema_applied() -> None:
    client = make_sync_client()
    try:
        assert client.command("SELECT 1") == 1
        # The reporter inserts into 'sboms'; verify the table exists.
        tables = client.query("SELECT name FROM system.tables WHERE database = currentDatabase()")
        names = {row[0] for row in tables.result_rows}
        assert {"sboms", "dependencies", "findings", "scan_metrics", "vex_statements"} <= names
    finally:
        client.close()


@pytest.mark.asyncio
async def test_valkey_reachable() -> None:
    import redis.asyncio as redis

    client = redis.Redis.from_url(get_settings().valkey_url, decode_responses=True)
    try:
        pong = await client.ping()
        assert pong
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_rustfs_health_ok() -> None:
    settings = get_settings()
    url = settings.s3_endpoint_url.rstrip("/") + "/health"
    async with httpx.AsyncClient(timeout=5.0) as http:
        r = await http.get(url)
    assert r.status_code == 200
    body = r.json()
    assert body.get("ready") is True
