"""Integration tests for multi-VCS source connections.

Require the compose stack (Postgres at minimum; the app lifespan also opens
ClickHouse + Valkey clients, which the integration env provides). Marked
``integration`` and excluded from the default ``just test`` run.

Covers:
- Source CRUD via the API (secret shown once, ciphertext at rest, delete 409).
- Per-connection webhook routing + verification.
- ``_resolve_source`` host-matching / ambiguity / anonymous fallback /
  explicit-id, exercised against throwaway orgs for isolation.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Iterator

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ippon.api._bootstrap import (
    AmbiguousConnectionError,
    ConnectionNotFoundError,
    _resolve_source,
)
from ippon.api.main import create_app
from ippon.config import Settings, get_settings
from ippon.db import async_session_scope, make_async_engine, make_async_session_factory
from ippon.models import (
    Org,
    Repository,
    SourceConnection,
    SourceCredentialType,
    SourceProvider,
)
from ippon.security import compute_hmac_sha256

pytestmark = pytest.mark.integration

_TOKEN = "test-token"
_AUTH = {"Authorization": f"Bearer {_TOKEN}"}


@pytest.fixture
def client() -> Iterator[TestClient]:
    settings = Settings(ippon_dev_token=_TOKEN)
    app = create_app(settings)
    with TestClient(app) as c:  # enters lifespan → real DB/CH/Valkey clients
        yield c


@pytest_asyncio.fixture
async def session() -> AsyncIterator[AsyncSession]:
    engine = make_async_engine(get_settings())
    factory = make_async_session_factory(engine)
    try:
        async with async_session_scope(factory) as s:
            yield s
    finally:
        await engine.dispose()


def _unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


# --- source CRUD -----------------------------------------------------------


def test_create_source_returns_secret_once_and_stores_ciphertext(client: TestClient) -> None:
    name = _unique("gh")
    r = client.post(
        "/sources",
        headers=_AUTH,
        json={
            "name": name,
            "provider": "github",
            "credential_type": "pat",
            "credential": "ghp_supersecret",
        },
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["has_credential"] is True
    assert body["webhook_configured"] is True
    assert body["webhook_url"].endswith(f"/webhooks/github/{body['id']}")
    assert body["webhook_secret"]  # shown once
    secret = body["webhook_secret"]

    # GET never echoes the secret or the credential.
    got = client.get(f"/sources/{body['id']}", headers=_AUTH)
    assert got.status_code == 200
    assert "webhook_secret" not in got.json()
    assert "credential" not in got.json()

    # Re-fetch via rotate to confirm the secret changes.
    rot = client.post(f"/sources/{body['id']}/rotate-webhook-secret", headers=_AUTH)
    assert rot.status_code == 200
    assert rot.json()["webhook_secret"] != secret


def test_create_rejects_credential_for_none_type(client: TestClient) -> None:
    r = client.post(
        "/sources",
        headers=_AUTH,
        json={
            "name": _unique("anon"),
            "provider": "github",
            "credential_type": "none",
            "credential": "should-not-be-here",
        },
    )
    assert r.status_code == 422


def test_create_rejects_duplicate_name(client: TestClient) -> None:
    name = _unique("dup")
    payload = {"name": name, "provider": "gitlab", "credential_type": "pat", "credential": "x"}
    assert client.post("/sources", headers=_AUTH, json=payload).status_code == 201
    again = client.post("/sources", headers=_AUTH, json=payload)
    assert again.status_code == 409


def test_list_sources_hides_secrets(client: TestClient) -> None:
    client.post(
        "/sources",
        headers=_AUTH,
        json={"name": _unique("ls"), "provider": "github", "credential_type": "none"},
    )
    r = client.get("/sources", headers=_AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["total"] >= 1
    for item in body["items"]:
        assert "webhook_secret" not in item
        assert "credential" not in item


@pytest.mark.asyncio
async def test_credential_blob_is_ciphertext(client: TestClient, session: AsyncSession) -> None:
    r = client.post(
        "/sources",
        headers=_AUTH,
        json={
            "name": _unique("cipher"),
            "provider": "github",
            "credential_type": "pat",
            "credential": "ghp_plaintext_marker",
        },
    )
    conn_id = uuid.UUID(r.json()["id"])
    conn = await session.get(SourceConnection, conn_id)
    assert conn is not None
    assert conn.credential_blob is not None
    assert b"ghp_plaintext_marker" not in conn.credential_blob


def test_delete_source_without_repos_succeeds(client: TestClient) -> None:
    r = client.post(
        "/sources",
        headers=_AUTH,
        json={"name": _unique("del"), "provider": "github", "credential_type": "none"},
    )
    sid = r.json()["id"]
    assert client.delete(f"/sources/{sid}", headers=_AUTH).status_code == 204
    assert client.get(f"/sources/{sid}", headers=_AUTH).status_code == 404


@pytest.mark.asyncio
async def test_delete_source_with_repos_conflicts(
    client: TestClient, session: AsyncSession
) -> None:
    r = client.post(
        "/sources",
        headers=_AUTH,
        json={"name": _unique("withrepo"), "provider": "github", "credential_type": "none"},
    )
    sid = uuid.UUID(r.json()["id"])
    org_id = uuid.UUID(r.json()["org_id"])
    session.add(
        Repository(
            org_id=org_id,
            source_connection_id=sid,
            remote_id=_unique("r"),
            full_name=_unique("owner/repo"),
            clone_url="https://github.com/owner/repo",
            default_branch="main",
        )
    )
    await session.commit()

    assert client.delete(f"/sources/{sid}", headers=_AUTH).status_code == 409


# --- per-connection webhook routing ---------------------------------------


def _create_github_connection(client: TestClient) -> tuple[str, str]:
    r = client.post(
        "/sources",
        headers=_AUTH,
        json={"name": _unique("wh"), "provider": "github", "credential_type": "none"},
    )
    body = r.json()
    return body["id"], body["webhook_secret"]


def test_github_webhook_accepts_valid_signature(client: TestClient) -> None:
    conn_id, secret = _create_github_connection(client)
    payload = b'{"action":"opened"}'
    sig = "sha256=" + compute_hmac_sha256(secret.encode(), payload)
    r = client.post(
        f"/webhooks/github/{conn_id}",
        headers={
            **_AUTH,
            "X-Hub-Signature-256": sig,
            "X-GitHub-Delivery": _unique("d"),
            "X-GitHub-Event": "push",
            "Content-Type": "application/json",
        },
        content=payload,
    )
    assert r.status_code == 202, r.text
    assert r.json()["status"] == "accepted"


def test_github_webhook_rejects_wrong_secret(client: TestClient) -> None:
    conn_id, _ = _create_github_connection(client)
    payload = b'{"action":"opened"}'
    sig = "sha256=" + compute_hmac_sha256(b"wrong-secret", payload)
    r = client.post(
        f"/webhooks/github/{conn_id}",
        headers={
            "X-Hub-Signature-256": sig,
            "X-GitHub-Delivery": _unique("d"),
            "X-GitHub-Event": "push",
        },
        content=payload,
    )
    assert r.status_code == 401


def test_github_webhook_unknown_connection_404(client: TestClient) -> None:
    payload = b"{}"
    sig = "sha256=" + compute_hmac_sha256(b"x", payload)
    r = client.post(
        f"/webhooks/github/{uuid.uuid4()}",
        headers={
            "X-Hub-Signature-256": sig,
            "X-GitHub-Delivery": _unique("d"),
            "X-GitHub-Event": "push",
        },
        content=payload,
    )
    assert r.status_code == 404


def test_webhook_provider_mismatch_400(client: TestClient) -> None:
    # A gitlab connection hit on the github route → 400.
    r = client.post(
        "/sources",
        headers=_AUTH,
        json={"name": _unique("gl"), "provider": "gitlab", "credential_type": "none"},
    )
    gl_id = r.json()["id"]
    resp = client.post(
        f"/webhooks/github/{gl_id}",
        headers={
            "X-Hub-Signature-256": "sha256=deadbeef",
            "X-GitHub-Delivery": _unique("d"),
            "X-GitHub-Event": "push",
        },
        content=b"{}",
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_delivery_row_records_connection(client: TestClient, session: AsyncSession) -> None:
    conn_id, secret = _create_github_connection(client)
    payload = b'{"action":"opened"}'
    delivery_id = _unique("d")
    sig = "sha256=" + compute_hmac_sha256(secret.encode(), payload)
    client.post(
        f"/webhooks/github/{conn_id}",
        headers={
            "X-Hub-Signature-256": sig,
            "X-GitHub-Delivery": delivery_id,
            "X-GitHub-Event": "push",
        },
        content=payload,
    )
    row = await session.scalar(
        select(SourceConnection).where(SourceConnection.id == uuid.UUID(conn_id))
    )
    assert row is not None
    from ippon.models import WebhookDelivery

    delivery = await session.scalar(
        select(WebhookDelivery).where(WebhookDelivery.delivery_id == delivery_id)
    )
    assert delivery is not None
    assert delivery.source_connection_id == uuid.UUID(conn_id)


# --- scan→connection resolution (_resolve_source, isolated orgs) -----------


async def _fresh_org(session: AsyncSession) -> Org:
    org = Org(slug=_unique("org"), name="Test Org")
    session.add(org)
    await session.flush()
    return org


def _add_conn(
    session: AsyncSession,
    org: Org,
    *,
    provider: SourceProvider,
    base_url: str | None,
    name: str,
) -> SourceConnection:
    conn = SourceConnection(
        org_id=org.id,
        name=name,
        provider=provider,
        credential_type=SourceCredentialType.none,
        base_url=base_url,
        credential_blob=None,
        webhook_secret_blob=None,
        credential_kid=None,
    )
    session.add(conn)
    return conn


@pytest.mark.asyncio
async def test_resolve_matches_by_host(session: AsyncSession) -> None:
    org = await _fresh_org(session)
    ghe = _add_conn(
        session, org, provider=SourceProvider.github, base_url="https://git.acme.com", name="ghe"
    )
    await session.flush()
    resolved = await _resolve_source(session, org, "https://git.acme.com/foo/bar", None)
    assert resolved.id == ghe.id


@pytest.mark.asyncio
async def test_resolve_anonymous_fallback(session: AsyncSession) -> None:
    org = await _fresh_org(session)
    resolved = await _resolve_source(session, org, "https://github.com/anchore/syft", None)
    assert resolved.name == "default-github"
    assert resolved.credential_type == SourceCredentialType.none


@pytest.mark.asyncio
async def test_resolve_ambiguous_raises(session: AsyncSession) -> None:
    org = await _fresh_org(session)
    _add_conn(session, org, provider=SourceProvider.github, base_url=None, name="gh-a")
    _add_conn(session, org, provider=SourceProvider.github, base_url=None, name="gh-b")
    await session.flush()
    with pytest.raises(AmbiguousConnectionError):
        await _resolve_source(session, org, "https://github.com/x/y", None)


@pytest.mark.asyncio
async def test_resolve_explicit_id(session: AsyncSession) -> None:
    org = await _fresh_org(session)
    a = _add_conn(session, org, provider=SourceProvider.github, base_url=None, name="gh-a")
    b = _add_conn(session, org, provider=SourceProvider.github, base_url=None, name="gh-b")
    await session.flush()
    resolved = await _resolve_source(session, org, "https://github.com/x/y", b.id)
    assert resolved.id == b.id
    assert resolved.id != a.id


@pytest.mark.asyncio
async def test_resolve_explicit_id_not_found(session: AsyncSession) -> None:
    org = await _fresh_org(session)
    with pytest.raises(ConnectionNotFoundError):
        await _resolve_source(session, org, "https://github.com/x/y", uuid.uuid4())
