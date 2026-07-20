"""Integration tests for the ``ApiToken`` model and token-management routes.

Require the compose stack (Postgres at minimum; the app lifespan also opens
ClickHouse + Valkey clients, which the integration env provides). Marked
``integration`` and excluded from the default ``just test`` run.

Uses the reusable ``client`` / ``session`` fixtures (copied from
``test_orgs.py``). Covers the ``ApiToken`` model round-trip, the
``authenticate_api_token`` helper, and the ``POST``/``GET``/``DELETE``
``/orgs/{org}/tokens`` routes (mint shows the secret once, list never echoes
it, delete soft-revokes so the token stops authenticating).
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ippon.api.authz import authenticate_api_token
from ippon.api.main import create_app
from ippon.config import Settings, get_settings
from ippon.db import async_session_scope, make_async_engine, make_async_session_factory
from ippon.models import ApiToken, OrgMemberRole
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
