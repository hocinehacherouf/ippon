"""ensure_dev_identity seeds a deterministic dev user + org + owner membership."""

from __future__ import annotations

import pytest
from sqlalchemy import delete, func, select

from ippon.api._bootstrap import ensure_dev_identity, get_or_create_default_org
from ippon.config import get_settings
from ippon.db import async_session_scope, make_async_engine, make_async_session_factory
from ippon.models import Org, OrgMember, OrgMemberRole
from ippon.security import DEV_ORG_ID, DEV_ORG_SLUG, DEV_USER_ID

pytestmark = pytest.mark.integration


async def test_ensure_dev_identity_is_idempotent() -> None:
    factory = make_async_session_factory(make_async_engine(get_settings()))
    async with async_session_scope(factory) as s:
        await ensure_dev_identity(s)
    async with async_session_scope(factory) as s:
        org = await ensure_dev_identity(s)  # second call must not duplicate
        assert org.id == DEV_ORG_ID
        member = await s.scalar(
            select(OrgMember).where(
                OrgMember.org_id == DEV_ORG_ID, OrgMember.user_id == DEV_USER_ID
            )
        )
        assert member is not None
        assert member.role == OrgMemberRole.owner


async def test_ensure_dev_identity_after_get_or_create_default_org_is_safe() -> None:
    """Regression: the two default-org creators must agree on one row.

    Previously ``get_or_create_default_org`` created an ``Org`` with a random
    id whenever it ran first, and ``ensure_dev_identity`` (keyed on the fixed
    ``DEV_ORG_ID``) would then try to insert a second ``slug="default"`` row
    on top of it, violating the ``orgs.slug`` unique constraint. Both now
    funnel through the same lookup/creation path, so running them in this
    order must be a no-op the second time, not a crash.

    The integration DB is shared across tests and never reset, so a dev org
    may already exist by the time this test runs (e.g. seeded by
    ``test_ensure_dev_identity_is_idempotent`` above). If we didn't clear it
    first, ``get_or_create_default_org`` below would just find that
    pre-existing row by slug and never exercise its CREATE branch at all —
    making this "regression" test pass trivially even with the old bug fully
    reintroduced. So we force the precondition: delete any existing
    ``slug="default"`` org (and its dependent members) up front, so the
    first call below is guaranteed to hit the CREATE branch.
    """
    factory = make_async_session_factory(make_async_engine(get_settings()))

    # Arrange: guarantee no `slug="default"` org exists yet, so
    # get_or_create_default_org is forced through its CREATE branch below
    # instead of finding a row left over from another test.
    async with async_session_scope(factory) as s:
        await s.execute(delete(OrgMember).where(OrgMember.org_id == DEV_ORG_ID))
        await s.execute(delete(Org).where(Org.slug == DEV_ORG_SLUG))

    async with async_session_scope(factory) as s:
        seeded_org = await get_or_create_default_org(s)  # now hits the CREATE branch

    async with async_session_scope(factory) as s:
        org = await ensure_dev_identity(s)  # must not raise a unique-constraint violation

    assert seeded_org.id == DEV_ORG_ID
    assert org.id == DEV_ORG_ID

    async with async_session_scope(factory) as s:
        count = await s.scalar(
            select(func.count()).select_from(Org).where(Org.slug == DEV_ORG_SLUG)
        )
        assert count == 1

        member = await s.scalar(
            select(OrgMember).where(
                OrgMember.org_id == DEV_ORG_ID, OrgMember.user_id == DEV_USER_ID
            )
        )
        assert member is not None
        assert member.role == OrgMemberRole.owner
