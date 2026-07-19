"""Tenancy authorization: resolve + enforce org membership and role."""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ippon.api.deps import CurrentUser, DbSession
from ippon.models import Org, OrgMember, OrgMemberRole
from ippon.security import Principal

_ROLE_RANK: dict[OrgMemberRole, int] = {
    OrgMemberRole.viewer: 0,
    OrgMemberRole.member: 1,
    OrgMemberRole.admin: 2,
    OrgMemberRole.owner: 3,
}


def role_at_least(role: OrgMemberRole, minimum: OrgMemberRole) -> bool:
    return _ROLE_RANK[role] >= _ROLE_RANK[minimum]


def _resolve_org_ref(ref: str) -> tuple[uuid.UUID | None, str | None]:
    """Interpret the `{org}` path segment as a UUID, else a slug."""
    try:
        return uuid.UUID(ref), None
    except ValueError:
        return None, ref


@dataclass(frozen=True)
class OrgContext:
    principal: Principal
    org_id: uuid.UUID
    role: OrgMemberRole


async def require_org_member(
    org: str,
    principal: CurrentUser,
    db: DbSession,
) -> OrgContext:
    """Authorize the caller's membership in `{org}`; 404 if org unknown or not a member."""
    org_id, slug = _resolve_org_ref(org)
    stmt = select(Org).where(Org.id == org_id) if org_id else select(Org).where(Org.slug == slug)
    org_row = await db.scalar(stmt)
    if org_row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="org not found")
    member = await db.scalar(
        select(OrgMember).where(
            OrgMember.org_id == org_row.id,
            OrgMember.user_id == principal.user_id,
        )
    )
    if member is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="org not found")
    return OrgContext(principal=principal, org_id=org_row.id, role=member.role)


OrgCtx = Annotated[OrgContext, Depends(require_org_member)]


def require_role(minimum: OrgMemberRole) -> Callable[[OrgContext], Awaitable[OrgContext]]:
    """Dependency factory: 403 unless the caller's role >= `minimum`."""

    async def _dep(ctx: OrgCtx) -> OrgContext:
        if not role_at_least(ctx.role, minimum):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"requires {minimum.value} role",
            )
        return ctx

    return _dep


async def get_scoped[T](db: AsyncSession, model: type[T], id_: uuid.UUID, ctx: OrgContext) -> T:
    """Fetch a row by id, but 404 unless it belongs to the caller's org."""
    obj = await db.get(model, id_)
    if obj is None or getattr(obj, "org_id", None) != ctx.org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    return obj
