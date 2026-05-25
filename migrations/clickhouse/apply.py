"""Idempotent ClickHouse migration applier.

Reads every ``NNNN_*.sql`` file under ``migrations/clickhouse/`` in numeric
order and applies it inside a single statement-by-statement loop. Applied
versions are recorded in a ``schema_versions`` table so re-runs are no-ops.

Usage:
    python migrations/clickhouse/apply.py

Connection details come from :class:`ippon.config.Settings.clickhouse_url`,
i.e. the ``CLICKHOUSE_URL`` env var.
"""

from __future__ import annotations

import logging
import re
import sys
from pathlib import Path

from clickhouse_connect.driver import Client

from ippon.clickhouse import make_sync_client

LOG = logging.getLogger("ippon.ch-migrate")
MIGRATIONS_DIR = Path(__file__).resolve().parent
VERSION_RE = re.compile(r"^(\d+)_.+\.sql$")


def split_statements(sql: str) -> list[str]:
    """Split a multi-statement SQL file into individual statements.

    ClickHouse's HTTP interface (which clickhouse-connect uses) accepts a
    single statement per request. We strip block comments and split on
    semicolons; this is enough for the schema we ship.
    """
    # Strip ``--`` line comments and ``/* ... */`` block comments.
    no_block = re.sub(r"/\*.*?\*/", "", sql, flags=re.DOTALL)
    no_line = re.sub(r"--[^\n]*", "", no_block)
    parts = [s.strip() for s in no_line.split(";")]
    return [p for p in parts if p]


def ensure_schema_versions_table(client: Client) -> None:
    client.command(
        """
        CREATE TABLE IF NOT EXISTS schema_versions (
            version    UInt32,
            applied_at DateTime DEFAULT now()
        ) ENGINE = MergeTree()
        ORDER BY version
        """
    )


def applied_versions(client: Client) -> set[int]:
    rows = client.query("SELECT DISTINCT version FROM schema_versions").result_rows
    return {int(row[0]) for row in rows}


def discover_migrations() -> list[tuple[int, Path]]:
    out: list[tuple[int, Path]] = []
    for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
        m = VERSION_RE.match(path.name)
        if not m:
            LOG.warning("skipping non-migration file: %s", path.name)
            continue
        out.append((int(m.group(1)), path))
    return out


def apply_one(client: Client, version: int, path: Path) -> None:
    LOG.info("applying %s", path.name)
    sql = path.read_text(encoding="utf-8")
    for stmt in split_statements(sql):
        client.command(stmt)
    client.insert("schema_versions", [[version]], column_names=["version"])
    LOG.info("applied version %d", version)


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    client = make_sync_client()

    # The default database may not yet exist on a brand-new ClickHouse — but
    # the docker-compose ``CLICKHOUSE_DB`` env creates it on first boot.
    ensure_schema_versions_table(client)

    done = applied_versions(client)
    pending = [(v, p) for v, p in discover_migrations() if v not in done]
    if not pending:
        LOG.info("clickhouse schema already at head (%d applied)", len(done))
        return 0

    for version, path in pending:
        apply_one(client, version, path)

    LOG.info(
        "clickhouse schema migrated: +%d (now %d total)", len(pending), len(done) + len(pending)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
