"""Sanity tests for the SQLAlchemy model registry."""

from __future__ import annotations

from ippon.models import Base


def test_metadata_has_expected_tables() -> None:
    expected = {
        "orgs",
        "users",
        "org_members",
        "source_connections",
        "repositories",
        "scan_policies",
        "scan_jobs",
        "webhook_deliveries",
    }
    assert expected.issubset(set(Base.metadata.tables.keys()))


def test_no_stray_tables() -> None:
    # Make sure we haven't accidentally pulled in unrelated tables (e.g. from
    # a third-party library defining things on Base).
    assert len(Base.metadata.tables) == 8
