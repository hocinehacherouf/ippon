"""GET /orgs/{org}/scans/{id}/secrets with a stubbed ClickHouse client."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ippon.api.authz import OrgContext, require_org_member
from ippon.api.deps import get_ch_client
from ippon.api.main import create_app
from ippon.config import Settings
from ippon.models import OrgMemberRole
from ippon.security import DEV_ORG_ID, DEV_PRINCIPAL


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
def app() -> Iterator[FastAPI]:
    application = create_app(Settings(ippon_dev_token="test-token"))
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
    application.dependency_overrides[get_ch_client] = lambda: _FakeCH(row)
    yield application
    application.dependency_overrides.clear()


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


def test_list_secrets_returns_redacted_rows(app: FastAPI, client: TestClient) -> None:
    # This unit test has no DB (no lifespan run), so the router-level
    # `require_org_member` dependency — which needs a live session to check
    # membership — is swapped for a fixed context. That isolates this test to
    # what it actually exercises: the ClickHouse read + redaction path.
    app.dependency_overrides[require_org_member] = lambda: OrgContext(
        principal=DEV_PRINCIPAL, org_id=DEV_ORG_ID, role=OrgMemberRole.owner
    )
    r = client.get(
        f"/orgs/{DEV_ORG_ID}/scans/{uuid4()}/secrets",
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
    # No bearer header and no `require_org_member` override: `require_user`
    # (the first sub-dependency of `require_org_member`) must 401 before any
    # DB access is attempted, since this unit test has no live session
    # factory (no lifespan run).
    r = client.get(f"/orgs/{DEV_ORG_ID}/scans/{uuid4()}/secrets")
    assert r.status_code == 401
