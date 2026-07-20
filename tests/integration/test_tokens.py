"""Integration tests for the ``ApiToken`` model and token-management routes.

Require the compose stack (Postgres at minimum; the app lifespan also opens
ClickHouse + Valkey clients, which the integration env provides). Marked
``integration`` and excluded from the default ``just test`` run.

Uses the reusable ``client`` / ``session`` fixtures (copied from
``test_orgs.py``). Covers the ``ApiToken`` model round-trip, the
``authenticate_api_token`` helper, and the ``POST``/``GET``/``DELETE``
``/orgs/{org}/tokens`` routes (mint shows the secret once, list never echoes
it, delete soft-revokes so the token stops authenticating).

The final section exercises minted tokens end-to-end as live bearer
credentials against other routers: role enforcement (member vs. admin),
org-binding (a token only authorizes the org it was minted for), post-revoke
401s, and the role-cannot-exceed-creator cap.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ippon.api.authz import authenticate_api_token
from ippon.api.main import create_app
from ippon.config import Settings, get_settings
from ippon.db import async_session_scope, make_async_engine, make_async_session_factory
from ippon.models import ApiToken, Org, OrgMemberRole
from ippon.security import DEV_ORG_ID, DEV_USER_ID, mint_api_token

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


async def test_api_token_round_trip(client: TestClient, session: AsyncSession) -> None:
    """Inserting an ``ApiToken`` persists every field and reads back unchanged."""
    # dev identity (org + user) is seeded by the client fixture's lifespan,
    # giving us valid FK targets for org_id / created_by_user_id.
    name = _uniq("ci-token")
    prefix = _uniq("ipn")
    token_hash = hashlib.sha256(uuid.uuid4().bytes).hexdigest()
    expires = datetime.now(UTC) + timedelta(days=30)

    token = ApiToken(
        org_id=DEV_ORG_ID,
        created_by_user_id=DEV_USER_ID,
        name=name,
        role=OrgMemberRole.member,
        token_prefix=prefix,
        token_sha256=token_hash,
        expires_at=expires,
    )
    session.add(token)
    await session.commit()
    token_id = token.id

    # Force a genuine reload from Postgres rather than trusting the identity map.
    session.expire_all()
    fetched = await session.scalar(select(ApiToken).where(ApiToken.id == token_id))

    assert fetched is not None
    assert fetched.org_id == DEV_ORG_ID
    assert fetched.created_by_user_id == DEV_USER_ID
    assert fetched.name == name
    assert fetched.role == OrgMemberRole.member
    assert fetched.token_prefix == prefix
    assert fetched.token_sha256 == token_hash
    assert fetched.last_used_at is None
    assert fetched.revoked_at is None
    assert fetched.expires_at is not None
    assert fetched.expires_at.replace(microsecond=0) == expires.replace(microsecond=0)
    assert fetched.created_at is not None
    assert fetched.updated_at is not None


async def test_api_token_prefix_unique(client: TestClient, session: AsyncSession) -> None:
    """``token_prefix`` has a unique index — a duplicate must fail to insert."""
    prefix = _uniq("ipn")
    first = ApiToken(
        org_id=DEV_ORG_ID,
        created_by_user_id=DEV_USER_ID,
        name=_uniq("tok"),
        role=OrgMemberRole.viewer,
        token_prefix=prefix,
        token_sha256=hashlib.sha256(uuid.uuid4().bytes).hexdigest(),
    )
    session.add(first)
    await session.commit()

    dup = ApiToken(
        org_id=DEV_ORG_ID,
        created_by_user_id=DEV_USER_ID,
        name=_uniq("tok"),
        role=OrgMemberRole.viewer,
        token_prefix=prefix,
        token_sha256=hashlib.sha256(uuid.uuid4().bytes).hexdigest(),
    )
    session.add(dup)
    with pytest.raises(IntegrityError):
        await session.commit()
    await session.rollback()  # leave the session usable for fixture teardown


async def _seed_token(
    session: AsyncSession,
    *,
    role: OrgMemberRole = OrgMemberRole.member,
    revoked_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> str:
    """Mint + persist an ``ApiToken`` for DEV_ORG_ID/DEV_USER_ID; return the full token."""
    full, prefix, token_hash = mint_api_token()
    session.add(
        ApiToken(
            org_id=DEV_ORG_ID,
            created_by_user_id=DEV_USER_ID,
            name=_uniq("auth-token"),
            role=role,
            token_prefix=prefix,
            token_sha256=token_hash,
            revoked_at=revoked_at,
            expires_at=expires_at,
        )
    )
    await session.commit()
    return full


async def test_authenticate_api_token_returns_token_principal(
    client: TestClient, session: AsyncSession
) -> None:
    """A live token authenticates to a ``kind="token"`` Principal carrying its org + role."""
    full = await _seed_token(session, role=OrgMemberRole.member)

    principal = await authenticate_api_token(session, full)

    assert principal is not None
    assert principal.kind == "token"
    assert principal.user_id == DEV_USER_ID
    assert principal.org_hint == DEV_ORG_ID
    assert principal.org_role == OrgMemberRole.member


async def test_authenticate_api_token_rejects_revoked(
    client: TestClient, session: AsyncSession
) -> None:
    full = await _seed_token(session, revoked_at=datetime.now(UTC))

    assert await authenticate_api_token(session, full) is None


async def test_authenticate_api_token_rejects_expired(
    client: TestClient, session: AsyncSession
) -> None:
    full = await _seed_token(session, expires_at=datetime.now(UTC) - timedelta(days=1))

    assert await authenticate_api_token(session, full) is None


async def test_authenticate_api_token_rejects_garbage_or_unknown_prefix(
    session: AsyncSession,
) -> None:
    # Not our token format at all.
    assert await authenticate_api_token(session, "not-an-ippon-token") is None
    # Right shape, but no such prefix has ever been minted.
    assert await authenticate_api_token(session, "ippon_pat_deadbeefcafe_bogus-secret") is None


async def test_authenticate_api_token_rejects_wrong_secret_for_known_prefix(
    session: AsyncSession,
) -> None:
    """Forgery resistance: a token with known prefix but wrong secret must be rejected."""
    # Mint a real token and persist it.
    _, prefix, secret_hash = mint_api_token()
    session.add(
        ApiToken(
            org_id=DEV_ORG_ID,
            created_by_user_id=DEV_USER_ID,
            name=_uniq("forgery-test-token"),
            role=OrgMemberRole.member,
            token_prefix=prefix,
            token_sha256=secret_hash,
        )
    )
    await session.commit()

    # Build a forged token: same prefix, wrong secret.
    forged = f"ippon_pat_{prefix}_totally-wrong-secret"

    # Constant-time hash comparison must reject it.
    assert await authenticate_api_token(session, forged) is None


# --- route-level CRUD (mint/list/revoke) -----------------------------------


async def test_create_list_revoke_token(client: TestClient, session: AsyncSession) -> None:
    """POST mints a token (shown once); GET lists metadata only; DELETE revokes it."""
    name = _uniq("route-token")
    created = client.post(
        f"/orgs/{DEV_ORG_ID}/tokens",
        headers=_AUTH,
        json={"name": name, "role": "member"},
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["token"].startswith("ippon_pat_")
    assert body["name"] == name
    assert body["role"] == "member"
    assert "token_sha256" not in body
    token_id = body["id"]
    full_token = body["token"]

    # GET lists it, with no secret or digest anywhere in the payload.
    listed = client.get(f"/orgs/{DEV_ORG_ID}/tokens", headers=_AUTH)
    assert listed.status_code == 200
    listed_body = listed.json()
    items_by_id = {item["id"]: item for item in listed_body["items"]}
    assert token_id in items_by_id
    for item in listed_body["items"]:
        assert "token" not in item
        assert "token_sha256" not in item

    # DELETE soft-revokes it.
    deleted = client.delete(f"/orgs/{DEV_ORG_ID}/tokens/{token_id}", headers=_AUTH)
    assert deleted.status_code == 204

    # A revoked token no longer authenticates.
    assert await authenticate_api_token(session, full_token) is None


# --- end-to-end: minted tokens as live bearer credentials -------------------
#
# Everything below mints a token through the route (as the dev owner, via
# ``_AUTH``) and then uses the returned plaintext ``token`` as the
# ``Authorization`` header for a *separate* call — proving the whole chain
# (parse → look up by prefix → verify digest → build a token ``Principal`` →
# ``require_org_member`` → ``require_role``) works from the outside, not just
# the ``authenticate_api_token`` helper in isolation.


def _mint_token(client: TestClient, role: str, *, name: str | None = None) -> Any:
    """Mint a token for DEV_ORG_ID via the route, as the dev owner; return the
    parsed creation response (carries the plaintext ``token`` once)."""
    r = client.post(
        f"/orgs/{DEV_ORG_ID}/tokens",
        headers=_AUTH,
        json={"name": name or _uniq("e2e-token"), "role": role},
    )
    assert r.status_code == 201, r.text
    return r.json()


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_token_can_scan_but_not_admin(client: TestClient) -> None:
    """A member-role token can do member-gated work (create a scan) but is
    refused admin-gated work (delete a source) — and the refusal is a pure
    role check: it fires before the (nonexistent) source is even looked up,
    so a random uuid4 still 403s rather than 404ing.

    The clone host is unique per run rather than a literal ``github.com``:
    DEV_ORG_ID is a long-lived shared fixture, and ``test_sources.py`` leaves
    behind several non-"default-" GitHub-host source connections it never
    deletes, so a fixed ``github.com`` URL hits ``_resolve_source``'s
    ambiguity guard (409) — a real conflict, just not the one this test is
    about. A fresh host per run falls through to the anonymous
    ``default-github`` connection deterministically, isolating the
    assertion to role enforcement.
    """
    minted = _mint_token(client, "member")
    auth = _bearer(minted["token"])

    scanned = client.post(
        f"/orgs/{DEV_ORG_ID}/scans",
        headers=auth,
        json={"repo_url": f"https://{_uniq('scan-host')}.example/x/y"},
    )
    assert scanned.status_code == 201, scanned.text

    deleted = client.delete(f"/orgs/{DEV_ORG_ID}/sources/{uuid.uuid4()}", headers=auth)
    assert deleted.status_code == 403


async def test_token_bound_to_its_org(client: TestClient, session: AsyncSession) -> None:
    """A token minted for DEV_ORG_ID is bound to it — presented against a
    different (existing) org, ``require_org_member`` 404s exactly as it
    would for a user who isn't a member there, rather than honoring the
    token's org-independent role.
    """
    minted = _mint_token(client, "member")
    auth = _bearer(minted["token"])

    foreign = Org(slug=_uniq("foreign-tok"), name="Foreign")
    session.add(foreign)
    await session.commit()

    r = client.get(f"/orgs/{foreign.id}/repos", headers=auth)
    assert r.status_code == 404


def test_revoked_token_gets_401(client: TestClient) -> None:
    """A live token authenticates (200); once revoked via the DELETE route,
    the identical bearer value is rejected outright (401) on the same call.
    """
    minted = _mint_token(client, "member")
    auth = _bearer(minted["token"])

    live = client.get(f"/orgs/{DEV_ORG_ID}/repos", headers=auth)
    assert live.status_code == 200

    revoked = client.delete(f"/orgs/{DEV_ORG_ID}/tokens/{minted['id']}", headers=_AUTH)
    assert revoked.status_code == 204

    after = client.get(f"/orgs/{DEV_ORG_ID}/repos", headers=auth)
    assert after.status_code == 401


def test_admin_token_can_mint_lesser_token(client: TestClient) -> None:
    """An admin-role token clears ``POST /tokens``'s ``require_role(admin)``
    gate — a genuinely admin-gated action (unlike ``/sources``, which is only
    member-gated) — and can mint a token at or below its own role. This is
    the positive control for the cap test below: it proves an admin token
    *passes* the admin gate, so the next test's 403 can be pinned on the cap
    instead.
    """
    minted = _mint_token(client, "admin")
    auth = _bearer(minted["token"])

    r = client.post(
        f"/orgs/{DEV_ORG_ID}/tokens",
        headers=auth,
        json={"name": _uniq("admin-minted"), "role": "member"},
    )
    assert r.status_code == 201, r.text
    assert r.json()["token"].startswith("ippon_pat_")


def test_admin_token_cannot_mint_owner_token(client: TestClient) -> None:
    """An admin-role token clears the route's ``require_role(admin)`` gate
    (admin tokens may mint tokens at all, per the test above) but still
    can't grant a role above its own — minting an ``owner`` token 403s on
    the ``role_at_least(ctx.role, body.role)`` cap in the handler, not the
    dependency gate. Asserting on the error message (not just the status
    code) pins the 403 on the cap's ``"cannot grant a role above your own"``
    detail, distinguishing it from the gate's own ``"requires admin role"``
    403 — both are 403s, so status code alone can't tell them apart.
    """
    minted = _mint_token(client, "admin")
    auth = _bearer(minted["token"])

    r = client.post(
        f"/orgs/{DEV_ORG_ID}/tokens",
        headers=auth,
        json={"name": _uniq("escalate"), "role": "owner"},
    )
    assert r.status_code == 403
    assert "above your own" in r.json()["error"]["message"]
