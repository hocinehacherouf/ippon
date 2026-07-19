"""Shared org/membership query helpers.

Read-only queries reused across the org, membership, and "me" routes (Tasks
3-5): the list of orgs a user belongs to (with their role in each), and the
owner count for an org (used to guard against demoting/removing the last
owner).
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ippon.models import Org, OrgMember, OrgMemberRole


async def list_memberships(db: AsyncSession, user_id: uuid.UUID) -> list[tuple[Org, OrgMemberRole]]:
    """Orgs ``user_id`` belongs to, paired with their role in each, slug-ordered."""
    rows = await db.execute(
        select(Org, OrgMember.role)
        .join(OrgMember, OrgMember.org_id == Org.id)
        .where(OrgMember.user_id == user_id)
        .order_by(Org.slug)
    )
    return [(org, role) for org, role in rows.all()]


async def count_owners(db: AsyncSession, org_id: uuid.UUID) -> int:
    """Number of ``owner``-role members in ``org_id`` (0 if none)."""
    n = await db.scalar(
        select(func.count())
        .select_from(OrgMember)
        .where(OrgMember.org_id == org_id, OrgMember.role == OrgMemberRole.owner)
    )
    return int(n or 0)
