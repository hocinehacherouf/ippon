"""Integration tests for the ``ApiToken`` model.

Require the compose stack (Postgres at minimum; the app lifespan also opens
ClickHouse + Valkey clients, which the integration env provides). Marked
``integration`` and excluded from the default ``just test`` run.

Starts with the reusable ``client`` / ``session`` fixtures (copied from
``test_orgs.py``) plus a round-trip test that inserts an ``ApiToken`` row via
the async session and reads it back. Later tasks extend this file with
route-level coverage (issue/list/revoke token endpoints).
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

from ippon.api.main import create_app
from ippon.config import Settings, get_settings
from ippon.db import async_session_scope, make_async_engine, make_async_session_factory
from ippon.models import ApiToken, OrgMemberRole
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
