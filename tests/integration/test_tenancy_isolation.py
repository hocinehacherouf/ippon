"""Cross-org isolation: a member of one org cannot read another org's resources.

Mirrors the fixture style in ``tests/integration/test_sources.py``: the
``client`` fixture enters ``TestClient`` as a context manager so the app
lifespan actually runs (seeding ``app.state`` DB/CH/Valkey clients and the
dev identity) — a plain ``httpx.ASGITransport`` client does NOT run the
lifespan, so ``app.state.session_factory`` would be missing and any DB route
would 500.

This file is intentionally kept small and its fixtures reusable — later
tasks (see Task 10) extend it with more cross-tenant checks (sources, scans).
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Iterator

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

from ippon.api.main import create_app
from ippon.config import Settings, get_settings
from ippon.db import async_session_scope, make_async_engine, make_async_session_factory
from ippon.models import Org, Repository, SourceConnection, SourceCredentialType, SourceProvider
from ippon.security import DEV_ORG_ID

pytestmark = pytest.mark.integration

_TOKEN = "test-token"
_AUTH = {"Authorization": f"Bearer {_TOKEN}"}


@pytest.fixture
def client() -> Iterator[TestClient]:
    settings = Settings(ippon_dev_token=_TOKEN)
    app = create_app(settings)
    with TestClient(app) as c:  # enters lifespan → real DB/CH/Valkey clients + dev identity seed
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


async def _seed_repo(session: AsyncSession, org_id: uuid.UUID, *, name: str) -> Repository:
    """Seed one repo (with its required ``SourceConnection``) under ``org_id``.

    ``Repository.source_connection_id`` is NOT NULL (FK to
    ``source_connections``), so a ``SourceConnection`` must be created first.
    """
    conn = SourceConnection(
        org_id=org_id,
        name=_unique("c"),
        provider=SourceProvider.github,
        credential_type=SourceCredentialType.none,
        base_url=None,
        credential_blob=None,
        webhook_secret_blob=None,
        credential_kid=None,
    )
    session.add(conn)
    await session.flush()
    repo = Repository(
        org_id=org_id,
        source_connection_id=conn.id,
        remote_id=_unique("r"),
        full_name=name,
        clone_url="https://github.com/x/y",
        default_branch="main",
    )
    session.add(repo)
    await session.commit()
    return repo


async def _seed_foreign_org(session: AsyncSession) -> uuid.UUID:
    """An org the dev user is NOT a member of."""
    other = Org(slug=_unique("other"), name="Other")
    session.add(other)
    await session.flush()
    return other.id


async def _seed_foreign_repo(session: AsyncSession) -> uuid.UUID:
    """An org the dev user is NOT a member of, containing one repo."""
    other_id = await _seed_foreign_org(session)
    await _seed_repo(session, other_id, name=_unique("x/y"))
    return other_id


@pytest.mark.asyncio
async def test_repos_of_other_org_forbidden(client: TestClient, session: AsyncSession) -> None:
    """The dev user is not a member of the seeded ``other`` org -> 404."""
    other_id = await _seed_foreign_repo(session)
    r = client.get(f"/orgs/{other_id}/repos", headers=_AUTH)
    assert r.status_code == 404


def test_repos_of_own_org_ok(client: TestClient) -> None:
    """The dev user is owner of ``DEV_ORG_ID`` -> 200."""
    r = client.get(f"/orgs/{DEV_ORG_ID}/repos", headers=_AUTH)
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_repo_by_id_from_other_org_is_404(client: TestClient, session: AsyncSession) -> None:
    """A repo id belonging to a different org 404s for a caller who IS a
    member of the org named in the path.

    ``require_org_member`` authorizes ``DEV_ORG_ID`` (the dev user owns it),
    so this only passes if ``get_scoped`` *also* rejects a repo id that
    resolves to a different org. This is the first live cross-org IDOR guard
    in the codebase; a regression to a bare ``db.get(Repository, id)`` (no
    org filter) would 200 here instead of 404.
    """
    other_id = await _seed_foreign_org(session)
    foreign_repo = await _seed_repo(session, other_id, name=_unique("other/repo"))

    r = client.get(f"/orgs/{DEV_ORG_ID}/repos/{foreign_repo.id}", headers=_AUTH)
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_repos_list_is_org_filtered(client: TestClient, session: AsyncSession) -> None:
    """The list endpoint's ``Repository.org_id == ctx.org_id`` filter actually
    excludes other orgs' repos, not just returns 200 for the caller's own.
    """
    dev_repo = await _seed_repo(session, DEV_ORG_ID, name=_unique("dev/repo"))
    other_id = await _seed_foreign_org(session)
    foreign_repo = await _seed_repo(session, other_id, name=_unique("other/repo"))

    r = client.get(f"/orgs/{DEV_ORG_ID}/repos", headers=_AUTH)
    assert r.status_code == 200
    full_names = {item["full_name"] for item in r.json()["items"]}
    assert dev_repo.full_name in full_names
    assert foreign_repo.full_name not in full_names
