"""Integration tests for org membership routes.

Require the compose stack (Postgres at minimum; the app lifespan also opens
ClickHouse + Valkey clients, which the integration env provides). Marked
``integration`` and excluded from the default ``just test`` run.

Fixtures (``client`` / ``session`` / ``_uniq`` / ``_AUTH`` / ``_TOKEN``) are
copied from ``test_orgs.py``. Task 7 extends this file with update/remove
member routes (owner/last-owner guards).
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

from ippon.api.main import create_app
from ippon.config import Settings, get_settings
from ippon.db import async_session_scope, make_async_engine, make_async_session_factory
from ippon.models import Org, OrgMember, OrgMemberRole
from ippon.security import DEV_USER_ID

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


def test_add_and_list_member(client: TestClient) -> None:
    org = client.post("/orgs", headers=_AUTH, json={"name": "M", "slug": _uniq("m")}).json()
    oid = org["id"]
    email = f"{_uniq('u')}@example.com"
    r = client.post(f"/orgs/{oid}/members", headers=_AUTH, json={"email": email, "role": "member"})
    assert r.status_code == 201, r.text
    assert r.json()["email"] == email and r.json()["role"] == "member"
    members = client.get(f"/orgs/{oid}/members", headers=_AUTH).json()
    assert any(m["email"] == email for m in members["items"])
    # owner (creator) is also listed
    assert any(m["role"] == "owner" for m in members["items"])


async def test_admin_cannot_grant_owner(client: TestClient, session: AsyncSession) -> None:
    """An admin (not owner) is blocked from granting the ``owner`` role.

    The caller passes the outer ``require_role(admin)`` gate (an admin, not
    a mere member/viewer), so a 403 here can only come from ``add_member``'s
    own owner-grant guard. A 404 would mean the seeded membership itself is
    wrong, not that the guard fired.
    """
    org = Org(slug=_uniq("ag"), name="AG")
    session.add(org)
    await session.flush()
    session.add(OrgMember(org_id=org.id, user_id=DEV_USER_ID, role=OrgMemberRole.admin))
    await session.commit()

    r = client.post(
        f"/orgs/{org.id}/members",
        headers=_AUTH,
        json={"email": f"{_uniq('n')}@e.com", "role": "owner"},
    )
    assert r.status_code == 403, r.text
    assert "owner" in r.json()["error"]["message"].lower()


def test_add_duplicate_member_409(client: TestClient) -> None:
    """Adding the same email a second time returns 409, not another 201."""
    org = client.post("/orgs", headers=_AUTH, json={"name": "D", "slug": _uniq("d")}).json()
    oid = org["id"]
    body = {"email": f"{_uniq('dup')}@example.com", "role": "member"}
    assert client.post(f"/orgs/{oid}/members", headers=_AUTH, json=body).status_code == 201
    r = client.post(f"/orgs/{oid}/members", headers=_AUTH, json=body)
    assert r.status_code == 409, r.text


async def test_members_of_other_org_forbidden(client: TestClient, session: AsyncSession) -> None:
    """A non-member of an org gets 404 (not 403/200) listing its members.

    ``require_org_member`` is applied at the router mount point, so an org
    the dev user has no ``OrgMember`` row for 404s before the handler runs.
    """
    org = Org(slug=_uniq("foreign"), name="Foreign")
    session.add(org)
    await session.commit()
    r = client.get(f"/orgs/{org.id}/members", headers=_AUTH)
    assert r.status_code == 404
