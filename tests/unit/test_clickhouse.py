"""Unit tests for the ClickHouse connection-param parser."""

from __future__ import annotations

import pytest

from ippon.clickhouse import ClickHouseConnectionParams


def test_parse_http_url() -> None:
    p = ClickHouseConnectionParams.from_url("http://alice:secret@ch.example:8123/analytics")
    assert p.host == "ch.example"
    assert p.port == 8123
    assert p.username == "alice"
    assert p.password == "secret"
    assert p.database == "analytics"
    assert p.secure is False


def test_parse_https_url_with_default_port() -> None:
    p = ClickHouseConnectionParams.from_url("https://ch.example/main")
    assert p.host == "ch.example"
    assert p.port == 8443
    assert p.username == "default"
    assert p.password == ""
    assert p.database == "main"
    assert p.secure is True


def test_rejects_non_http_scheme() -> None:
    with pytest.raises(ValueError, match="scheme"):
        ClickHouseConnectionParams.from_url("tcp://ch.example:9000/main")


def test_rejects_missing_host() -> None:
    with pytest.raises(ValueError, match="host"):
        ClickHouseConnectionParams.from_url("http:///main")
