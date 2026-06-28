"""GET /scans/{id}/secrets with a stubbed ClickHouse client."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from ippon.api.deps import get_ch_client
from ippon.api.main import create_app
from ippon.config import Settings


class _FakeResult:
    def __init__(self, rows: list[list[Any]]) -> None:
        self.result_rows = rows


class _FakeCH:
    def __init__(self, row: list[Any]) -> None:
        self._row = row

    def query(self, sql: str, parameters: dict[str, Any] | None = None) -> _FakeResult:
        if "count()" in sql:
            return _FakeResult([[1]])
        return _FakeResult([self._row])


@pytest.fixture
def client() -> Iterator[TestClient]:
    app = create_app(Settings(ippon_dev_token="test-token"))
    scan_id = uuid4()
    row = [
        scan_id,  # scan_id
        "aws-access-token",  # rule_id
        "AWS Access Key",  # description
        "config/old.env",  # file
        3,  # start_line
        3,  # end_line
        "aws_access_key_id=REDACTED",  # match
        "1111:config/old.env:aws-access-token:3",  # fingerprint
        "Old Dev",  # author
        "old@example.com",  # email
        datetime(2024, 1, 2, tzinfo=UTC),  # committed_at
        ["k"],  # tags
        False,  # verified
        "unverified",  # validation_status
        True,  # is_historical
        datetime.now(UTC),  # scanned_at
    ]
    app.dependency_overrides[get_ch_client] = lambda: _FakeCH(row)
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_list_secrets_returns_redacted_rows(client: TestClient) -> None:
    r = client.get(
        f"/scans/{uuid4()}/secrets",
        headers={"Authorization": "Bearer test-token"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 1
    item = body["items"][0]
    assert item["rule_id"] == "aws-access-token"
    assert "REDACTED" in item["match"]
    assert item["is_historical"] is True
    assert item["verified"] is False


def test_list_secrets_requires_auth(client: TestClient) -> None:
    r = client.get(f"/scans/{uuid4()}/secrets")
    assert r.status_code == 401
