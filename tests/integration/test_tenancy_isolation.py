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
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

from ippon.api.main import create_app
from ippon.clickhouse import make_sync_client
from ippon.config import Settings, get_settings
from ippon.db import async_session_scope, make_async_engine, make_async_session_factory
from ippon.models import (
    JobRunnerBackend,
    Org,
    Repository,
    ScanJob,
    ScanJobStatus,
    ScanTrigger,
    SourceConnection,
    SourceCredentialType,
    SourceProvider,
)
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


async def _seed_scan(session: AsyncSession, org_id: uuid.UUID, repository_id: uuid.UUID) -> ScanJob:
    """Seed one queued scan job under ``org_id`` for ``repository_id``."""
    scan = ScanJob(
        org_id=org_id,
        repository_id=repository_id,
        status=ScanJobStatus.queued,
        trigger=ScanTrigger.manual,
        backend=JobRunnerBackend.docker,
        requested_ref="HEAD",
        callback_secret="x",
    )
    session.add(scan)
    await session.commit()
    return scan


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


@pytest.mark.asyncio
async def test_source_by_id_from_other_org_is_404(
    client: TestClient, session: AsyncSession
) -> None:
    """A source-connection id belonging to a different org 404s for a caller
    who IS a member of the org named in the path — same IDOR guard as
    ``test_repo_by_id_from_other_org_is_404``, now for sources.
    """
    other_id = await _seed_foreign_org(session)
    conn = SourceConnection(
        org_id=other_id,
        name=_unique("c"),
        provider=SourceProvider.github,
        credential_type=SourceCredentialType.none,
        base_url=None,
        credential_blob=None,
        webhook_secret_blob=None,
        credential_kid=None,
    )
    session.add(conn)
    await session.commit()

    r = client.get(f"/orgs/{DEV_ORG_ID}/sources/{conn.id}", headers=_AUTH)
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_scan_by_id_from_other_org_is_404(client: TestClient, session: AsyncSession) -> None:
    """A scan id belonging to a different org 404s for a caller who IS a
    member of the org named in the path — same IDOR guard as
    ``test_repo_by_id_from_other_org_is_404`` / ``test_source_by_id_from_other_org_is_404``,
    now for scans.
    """
    other_id = await _seed_foreign_org(session)
    foreign_repo = await _seed_repo(session, other_id, name=_unique("other/repo"))
    foreign_scan = await _seed_scan(session, other_id, foreign_repo.id)

    r = client.get(f"/orgs/{DEV_ORG_ID}/scans/{foreign_scan.id}", headers=_AUTH)
    assert r.status_code == 404


def test_findings_are_org_scoped(client: TestClient) -> None:
    """``GET /orgs/{org}/scans/{id}/findings`` applies the ``ch_scoped`` org
    predicate against real ClickHouse without error, returning an empty page
    (rather than erroring or leaking rows) for a scan id that doesn't exist.
    """
    r = client.get(f"/orgs/{DEV_ORG_ID}/scans/{uuid.uuid4()}/findings", headers=_AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 0


_FINDINGS_COLUMNS = [
    "scan_id",
    "org_id",
    "repo_id",
    "commit_sha",
    "cve_id",
    "purl",
    "name",
    "version",
    "severity",
    "fix_state",
    "fix_versions",
    "description",
    "cvss_score",
    "cvss_vector",
    "matcher",
    "scanned_at",
]


def test_findings_exclude_other_orgs(client: TestClient) -> None:
    """Genuine proof that ``list_findings``'s ``ch_scoped`` predicate excludes
    another org's rows — unlike ``test_findings_are_org_scoped`` above, which
    only queries a scan id with zero rows at all (so it would pass whether or
    not the ``org_id`` filter exists).

    Inserts two ``findings`` rows directly into ClickHouse that share one
    ``scan_id`` but belong to two different orgs, then asserts the API (as
    the dev user, a member of ``DEV_ORG_ID``) returns only the dev org's row.
    ClickHouse ``findings`` rows aren't FK-checked, so ``other_org_id`` need
    not exist in Postgres — a bare ``uuid.uuid4()`` is enough to prove the
    predicate. If ``ch_scoped(ctx.org_id, params)`` were dropped from
    ``list_findings`` (leaving only ``scan_id = {scan_id:UUID}``), both rows
    would match and ``total`` would be 2, failing this test.
    """
    scan_id = uuid.uuid4()
    other_org_id = uuid.uuid4()
    scanned_at = datetime.now(UTC)

    dev_row = [
        scan_id,
        DEV_ORG_ID,
        uuid.uuid4(),
        "deadbeef",
        "CVE-DEV-0001",
        "pkg:pypi/dev-pkg@1.0.0",
        "dev-pkg",
        "1.0.0",
        "high",
        "fixed",
        ["1.1.0"],
        "dev org finding",
        7.5,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "python-matcher",
        scanned_at,
    ]
    other_row = [
        scan_id,
        other_org_id,
        uuid.uuid4(),
        "deadbeef",
        "CVE-OTHER-0001",
        "pkg:pypi/other-pkg@2.0.0",
        "other-pkg",
        "2.0.0",
        "critical",
        "not-fixed",
        ["3.0.0"],
        "other org finding",
        9.8,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "python-matcher",
        scanned_at,
    ]

    ch = make_sync_client(get_settings())
    try:
        ch.insert("findings", [dev_row, other_row], column_names=_FINDINGS_COLUMNS)
    finally:
        ch.close()

    r = client.get(f"/orgs/{DEV_ORG_ID}/scans/{scan_id}/findings", headers=_AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 1
    assert len(body["items"]) == 1
    assert body["items"][0]["cve_id"] == "CVE-DEV-0001"
