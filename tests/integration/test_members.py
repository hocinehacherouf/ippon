"""Integration tests for org membership routes.

Require the compose stack (Postgres at minimum; the app lifespan also opens
ClickHouse + Valkey clients, which the integration env provides). Marked
``integration`` and excluded from the default ``just test`` run.

Fixtures (``client`` / ``session`` / ``_uniq`` / ``_AUTH`` / ``_TOKEN``) are
copied from ``test_orgs.py``. Task 7 extends this file with update/remove
member routes (owner/last-owner guards). Task 8 adds an end-to-end
``require_role`` gate check plus coverage for the ``bootstrap`` CLI.
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
from ippon.models import Org, OrgMember, OrgMemberRole, User
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


def test_change_role_and_remove(client: TestClient) -> None:
    oid = client.post("/orgs", headers=_AUTH, json={"name": "R", "slug": _uniq("r")}).json()["id"]
    email = f"{_uniq('m')}@example.com"
    uid = client.post(
        f"/orgs/{oid}/members", headers=_AUTH, json={"email": email, "role": "member"}
    ).json()["user_id"]
    assert (
        client.patch(f"/orgs/{oid}/members/{uid}", headers=_AUTH, json={"role": "admin"}).json()[
            "role"
        ]
        == "admin"
    )
    assert client.delete(f"/orgs/{oid}/members/{uid}", headers=_AUTH).status_code == 204


def test_cannot_remove_last_owner(client: TestClient) -> None:
    oid = client.post("/orgs", headers=_AUTH, json={"name": "O", "slug": _uniq("o")}).json()["id"]
    # the creator (dev user) is the sole owner
    r = client.delete(f"/orgs/{oid}/members/{DEV_USER_ID}", headers=_AUTH)
    assert r.status_code == 409
    # and can't be demoted
    assert (
        client.patch(
            f"/orgs/{oid}/members/{DEV_USER_ID}", headers=_AUTH, json={"role": "admin"}
        ).status_code
        == 409
    )


@pytest.mark.integration
async def test_admin_cannot_modify_or_grant_owner(
    client: TestClient, session: AsyncSession
) -> None:
    """An admin (not owner) is blocked from demoting/removing an owner or granting owner.

    Both existing Task 7 tests (``test_change_role_and_remove`` and
    ``test_cannot_remove_last_owner``) call as the org owner, so the
    ``ctx.role != owner`` branch of the escalation guard on ``update_member``
    / ``remove_member`` is never exercised. Seed the dev user as an ``admin``
    alongside a real ``owner`` and a plain ``member`` so the caller clears
    the outer ``require_role(admin)`` gate but still hits the owner-touch
    guard. A 404 here would mean the seeded membership is wrong; a 200/204
    would be a real privilege-escalation bug.
    """
    org = Org(slug=_uniq("esc"), name="Esc")
    session.add(org)
    await session.flush()
    owner_user = User(email=f"{_uniq('own')}@e.com")
    member_user = User(email=f"{_uniq('mem')}@e.com")
    session.add_all([owner_user, member_user])
    await session.flush()
    session.add_all(
        [
            OrgMember(org_id=org.id, user_id=DEV_USER_ID, role=OrgMemberRole.admin),
            OrgMember(org_id=org.id, user_id=owner_user.id, role=OrgMemberRole.owner),
            OrgMember(org_id=org.id, user_id=member_user.id, role=OrgMemberRole.member),
        ]
    )
    await session.commit()

    # demoting an owner
    r = client.patch(
        f"/orgs/{org.id}/members/{owner_user.id}", headers=_AUTH, json={"role": "admin"}
    )
    assert r.status_code == 403, r.text

    # removing an owner
    r = client.delete(f"/orgs/{org.id}/members/{owner_user.id}", headers=_AUTH)
    assert r.status_code == 403, r.text

    # granting owner to a plain member
    r = client.patch(
        f"/orgs/{org.id}/members/{member_user.id}", headers=_AUTH, json={"role": "owner"}
    )
    assert r.status_code == 403, r.text


async def test_member_cannot_add_member(client: TestClient, session: AsyncSession) -> None:
    """A plain ``member`` (below the ``admin`` minimum) is blocked from adding
    another member.

    Unlike ``test_members_of_other_org_forbidden``, the caller here IS a
    member of the org (so ``require_org_member`` passes, not a 404) — the 403
    can only come from ``add_member``'s ``require_role(OrgMemberRole.admin)``
    dependency rejecting a role that ranks below ``admin``.
    """
    org = Org(slug=_uniq("mem"), name="Mem")
    session.add(org)
    await session.flush()
    session.add(OrgMember(org_id=org.id, user_id=DEV_USER_ID, role=OrgMemberRole.member))
    await session.commit()

    r = client.post(
        f"/orgs/{org.id}/members",
        headers=_AUTH,
        json={"email": f"{_uniq('x')}@e.com", "role": "member"},
    )
    assert r.status_code == 403  # member < admin


def test_bootstrap_creates_org_and_owner(client: TestClient) -> None:
    """``bootstrap.main`` find-or-creates the org/user/owner-membership and is
    idempotent — re-running with identical arguments must hit the
    "already exists" branch for all three instead of tripping a unique
    constraint (``orgs.slug``, ``users.email``, ``org_members(org_id, user_id)``).
    """
    from ippon.scripts.bootstrap import main

    slug = _uniq("boot")
    rc = main(["--org-slug", slug, "--org-name", "Boot", "--owner-email", "boss@example.com"])
    assert rc == 0
    assert (
        main(["--org-slug", slug, "--org-name", "Boot", "--owner-email", "boss@example.com"]) == 0
    )
