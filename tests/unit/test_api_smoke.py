"""API smoke tests using FastAPI's TestClient.

These don't touch the lifespan (TestClient runs lifespan startup/shutdown
which would try to open real DB/Redis/CH connections); we use TestClient as
an ASGI test driver but only hit routes that don't depend on ``app.state``.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from ippon.api.main import create_app
from ippon.config import Settings


@pytest.fixture
def client() -> Iterator[TestClient]:
    app = create_app(Settings(ippon_dev_token="test-token"))
    # Deliberately NOT entering the TestClient as a context manager: that
    # would trigger lifespan startup and try to open real DB/Valkey/CH
    # connections. ``app.state.settings`` is set in ``create_app`` itself,
    # so auth-protected routes work without a live infra stack.
    yield TestClient(app)


def test_health_returns_ok(client: TestClient) -> None:
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_openapi_doc_renders(client: TestClient) -> None:
    r = client.get("/openapi.json")
    assert r.status_code == 200
    spec = r.json()
    assert spec["info"]["title"] == "ippon"
    # All seven tag groups should be advertised.
    tag_names = {t["name"] for t in spec.get("tags", [])}
    assert {"health", "auth", "orgs", "sources", "repos", "scans", "webhooks"} <= tag_names


def test_docs_page_renders(client: TestClient) -> None:
    r = client.get("/docs")
    assert r.status_code == 200
    assert "Swagger UI" in r.text or "swagger-ui" in r.text


def test_request_id_header_added(client: TestClient) -> None:
    r = client.get("/health")
    assert "x-request-id" in {k.lower() for k in r.headers}


def test_request_id_propagated(client: TestClient) -> None:
    r = client.get("/health", headers={"X-Request-Id": "test-rid-1"})
    assert r.headers.get("x-request-id") == "test-rid-1"


def test_protected_route_requires_bearer(client: TestClient) -> None:
    r = client.get("/orgs")
    assert r.status_code == 401
    body = r.json()
    assert body["error"]["code"] == 401


def test_protected_route_rejects_bad_token(client: TestClient) -> None:
    r = client.get("/orgs", headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 401


def test_protected_route_accepts_good_token(client: TestClient) -> None:
    r = client.get("/orgs", headers={"Authorization": "Bearer test-token"})
    # 501 placeholder is what we expect — auth passed, but the route is a stub.
    assert r.status_code == 501


def test_structured_error_includes_request_id(client: TestClient) -> None:
    r = client.get("/orgs", headers={"X-Request-Id": "rid-err-1"})
    assert r.status_code == 401
    assert r.json()["error"]["request_id"] == "rid-err-1"
