"""ClickHouse client factories.

The API uses ``asynch`` (async); workers, the migration applier, and the
reporter use ``clickhouse-connect`` (sync). The two libraries take connection
parameters differently, so this module parses ``settings.clickhouse_url`` once
and exposes a typed parameter bag.

VEX read pattern
================

``vex_statements`` is a ``ReplacingMergeTree(updated_at, is_deleted)``: the same
``(org_id, cve_id, purl, id)`` may appear multiple times in the parts (one row
per edit), with only the highest ``updated_at`` representing the current state.

When querying VEX from the API, **always** apply one of:

1. ``SELECT ... FROM vex_statements FINAL WHERE is_deleted = 0`` — easy but
   reads all parts.
2. ``argMax(col, updated_at)`` for each column with ``GROUP BY id`` and a
   final ``HAVING argMax(is_deleted, updated_at) = 0`` — fast on wide tables.

Inserts to ``vex_statements`` are append-only — never DELETE. Edits insert a
new row with the same ``id`` and a fresh ``updated_at``. Soft-deletes insert a
tombstone row with ``is_deleted = 1``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import clickhouse_connect
from clickhouse_connect.driver import Client as SyncClient

from ippon.config import Settings, get_settings


@dataclass(frozen=True)
class ClickHouseConnectionParams:
    """Resolved connection parameters parsed from ``settings.clickhouse_url``."""

    host: str
    port: int
    username: str
    password: str
    database: str
    secure: bool

    @classmethod
    def from_url(cls, url: str) -> ClickHouseConnectionParams:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError(f"clickhouse_url must use http(s) scheme, got {parsed.scheme!r}")
        if not parsed.hostname:
            raise ValueError("clickhouse_url is missing a host")
        return cls(
            host=parsed.hostname,
            port=parsed.port or (8443 if parsed.scheme == "https" else 8123),
            username=parsed.username or "default",
            password=parsed.password or "",
            database=parsed.path.lstrip("/") or "default",
            secure=parsed.scheme == "https",
        )


def get_connection_params(settings: Settings | None = None) -> ClickHouseConnectionParams:
    settings = settings or get_settings()
    return ClickHouseConnectionParams.from_url(settings.clickhouse_url)


def make_sync_client(settings: Settings | None = None, **overrides: Any) -> SyncClient:
    """Return a sync ``clickhouse-connect`` client.

    Use this in workers, the migration applier, and the reporter.
    """
    params = get_connection_params(settings)
    return clickhouse_connect.get_client(
        host=params.host,
        port=params.port,
        username=params.username,
        password=params.password,
        database=params.database,
        secure=params.secure,
        **overrides,
    )
