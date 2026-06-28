"""The 0002 ClickHouse migration is discoverable and well-formed."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parents[2]
MIGRATION = REPO_ROOT / "migrations" / "clickhouse" / "0002_secret_findings.sql"


def _load_apply() -> ModuleType:
    path = REPO_ROOT / "migrations" / "clickhouse" / "apply.py"
    spec = importlib.util.spec_from_file_location("ch_apply", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_migration_0002_is_discovered() -> None:
    apply = _load_apply()
    versions = {v for v, _ in apply.discover_migrations()}
    assert 2 in versions


def test_migration_0002_statements_are_wellformed() -> None:
    apply = _load_apply()
    stmts = apply.split_statements(MIGRATION.read_text(encoding="utf-8"))
    assert all(s.strip() for s in stmts), "no empty statements"
    assert any("CREATE TABLE IF NOT EXISTS secret_findings" in s for s in stmts)
    assert any("ADD COLUMN IF NOT EXISTS secret_finding_count" in s for s in stmts)
    assert any("ADD COLUMN IF NOT EXISTS verified_secret_count" in s for s in stmts)
