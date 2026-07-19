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
from ippon.models import OrgMemberRole
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
