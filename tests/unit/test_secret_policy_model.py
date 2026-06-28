"""ScanPolicy secret-scan columns + defaults."""

from __future__ import annotations

from ippon.models import ScanPolicy


def test_scan_policy_has_secret_columns() -> None:
    cols = ScanPolicy.__table__.columns
    assert "secret_scan_enabled" in cols
    assert "verify_secrets" in cols
    assert "secret_history_depth" in cols


def test_scan_policy_secret_column_defaults() -> None:
    cols = ScanPolicy.__table__.columns
    assert cols["secret_scan_enabled"].default.arg is True
    assert cols["verify_secrets"].default.arg is False
    assert cols["secret_history_depth"].default.arg == 256
