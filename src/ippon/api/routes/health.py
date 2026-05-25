"""Liveness and readiness probes.

- ``GET /health``: liveness — returns 200 as long as the process is running.
- ``GET /ready``: readiness — checks Postgres, ClickHouse, Valkey, RustFS.
  Returns 200 only if every probe succeeds; otherwise 503 with per-check
  detail so an operator can diagnose without grepping logs.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
from clickhouse_connect.driver import Client as CHClient
from fastapi import APIRouter
from fastapi.responses import JSONResponse
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ippon.api.deps import CHDep, DbSession, RedisDep, SettingsDep
from ippon.config import Settings

router = APIRouter(tags=["health"])


@router.get("/health", summary="Liveness probe")
async def health() -> dict[str, str]:
    return {"status": "ok"}


async def _check_postgres(session: AsyncSession) -> tuple[bool, str | None]:
    try:
        await session.execute(text("SELECT 1"))
        return True, None
    except Exception as exc:  # pragma: no cover — error path
        return False, f"{type(exc).__name__}: {exc}"


async def _check_clickhouse(client: CHClient) -> tuple[bool, str | None]:
    try:
        await asyncio.to_thread(client.command, "SELECT 1")
        return True, None
    except Exception as exc:  # pragma: no cover
        return False, f"{type(exc).__name__}: {exc}"


async def _check_valkey(client: Redis) -> tuple[bool, str | None]:
    try:
        # redis-py's async ``ping`` returns ``Awaitable[bool] | bool`` per the
        # stubs; in practice it always returns ``True`` or raises.
        pong = await client.ping()  # type: ignore[misc]
        if not pong:
            return False, "PING did not return PONG"
        return True, None
    except Exception as exc:  # pragma: no cover
        return False, f"{type(exc).__name__}: {exc}"


async def _check_rustfs(settings: Settings) -> tuple[bool, str | None]:
    url = settings.s3_endpoint_url.rstrip("/") + "/health"
    try:
        async with httpx.AsyncClient(timeout=2.0) as http:
            r = await http.get(url)
        if r.status_code != httpx.codes.OK:
            return False, f"{url} returned {r.status_code}"
        return True, None
    except Exception as exc:  # pragma: no cover
        return False, f"{type(exc).__name__}: {exc}"


@router.get(
    "/ready",
    summary="Readiness probe",
    responses={
        200: {"description": "All dependencies reachable."},
        503: {"description": "One or more dependencies unreachable."},
    },
)
async def ready(
    session: DbSession,
    redis_client: RedisDep,
    ch: CHDep,
    settings: SettingsDep,
) -> JSONResponse:
    pg_ok, pg_err = await _check_postgres(session)
    ch_ok, ch_err = await _check_clickhouse(ch)
    rd_ok, rd_err = await _check_valkey(redis_client)
    s3_ok, s3_err = await _check_rustfs(settings)

    checks: dict[str, dict[str, Any]] = {
        "postgres": {"ok": pg_ok, "error": pg_err},
        "clickhouse": {"ok": ch_ok, "error": ch_err},
        "valkey": {"ok": rd_ok, "error": rd_err},
        "rustfs": {"ok": s3_ok, "error": s3_err},
    }
    healthy = all(c["ok"] for c in checks.values())
    return JSONResponse(
        status_code=200 if healthy else 503,
        content={"status": "ready" if healthy else "degraded", "checks": checks},
    )
