"""Integration tests for org/membership queries and routes.

Require the compose stack (Postgres at minimum; the app lifespan also opens
ClickHouse + Valkey clients, which the integration env provides). Marked
``integration`` and excluded from the default ``just test`` run.

Starts with the reusable ``client`` / ``session`` fixtures plus a focused
test for the shared query helpers in ``orgs_service``. Tasks 3-5 extend this
file with route-level coverage (list/create/get org, membership CRUD, "me").
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

from ippon.api.main import create_app
from ippon.api.orgs_service import count_owners, list_memberships
from ippon.config import Settings, get_settings
from ippon.db import async_session_scope, make_async_engine, make_async_session_factory
from ippon.models import Org, OrgMemberRole
from ippon.security import DEV_ORG_ID, DEV_USER_ID

pytestmark = pytest.mark.integration

_TOKEN = "test-token"
_AUTH = {"Authorization": f"Bearer {_TOKEN}"}


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(create_app(Settings(ippon_dev_token=_TOKEN))) as c:  # enters lifespan
        yield c


@pytest.fixture
async def session() -> AsyncIterator[AsyncSession]:
    engine = make_async_engine(get_settings())
    try:
        async with async_session_scope(make_async_session_factory(engine)) as s:
            yield s
    finally:
        await engine.dispose()


def _uniq(p: str) -> str:
    return f"{p}-{uuid.uuid4().hex[:8]}"


async def test_service_counts_and_memberships(client: TestClient, session: AsyncSession) -> None:
    # dev identity is seeded by the client fixture's lifespan
    owners = await count_owners(session, DEV_ORG_ID)
    assert owners >= 1
    mems = await list_memberships(session, DEV_USER_ID)
    assert any(org.id == DEV_ORG_ID and role == OrgMemberRole.owner for org, role in mems)


async def test_me_lists_memberships(client: TestClient) -> None:
    r = client.get("/me", headers=_AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["user_id"] == str(DEV_USER_ID)
    assert any(m["org_id"] == str(DEV_ORG_ID) and m["role"] == "owner" for m in body["memberships"])


def test_me_requires_auth(client: TestClient) -> None:
    assert client.get("/me").status_code == 401


def test_create_org_makes_caller_owner(client: TestClient) -> None:
    slug = _uniq("acme")
    r = client.post("/orgs", headers=_AUTH, json={"name": "Acme", "slug": slug})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["slug"] == slug and body["role"] == "owner"
    # appears in my list
    lst = client.get("/orgs", headers=_AUTH).json()
    assert any(o["slug"] == slug for o in lst["items"])


def test_create_org_duplicate_slug_409(client: TestClient) -> None:
    slug = _uniq("dup")
    assert client.post("/orgs", headers=_AUTH, json={"name": "A", "slug": slug}).status_code == 201
    assert client.post("/orgs", headers=_AUTH, json={"name": "B", "slug": slug}).status_code == 409


def test_get_patch_delete_org(client: TestClient) -> None:
    slug = _uniq("crud")
    org = client.post("/orgs", headers=_AUTH, json={"name": "C", "slug": slug}).json()
    oid = org["id"]
    assert client.get(f"/orgs/{oid}", headers=_AUTH).json()["slug"] == slug
    r = client.patch(f"/orgs/{oid}", headers=_AUTH, json={"name": "Renamed"})
    assert r.status_code == 200 and r.json()["name"] == "Renamed"
    assert client.delete(f"/orgs/{oid}", headers=_AUTH).status_code == 204
    assert client.get(f"/orgs/{oid}", headers=_AUTH).status_code == 404


async def test_get_org_non_member_404(client: TestClient, session: AsyncSession) -> None:
    """An org the dev user is NOT a member of -> 404 (not 403 or 200), same
    as the other org-scoped routes (mirrors the foreign-org seed in
    ``test_tenancy_isolation.py``).
    """
    org = Org(slug=_uniq("foreign"), name="Foreign")
    session.add(org)
    await session.commit()
    r = client.get(f"/orgs/{org.id}", headers=_AUTH)
    assert r.status_code == 404
