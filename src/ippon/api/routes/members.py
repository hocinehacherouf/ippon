"""Org membership routes.

Mounted under ``/orgs/{org}/members`` (``require_org_member`` is applied at
the mount point in ``main.py``, same as ``orgs.detail_router``).

``GET`` (any member) lists the org's members. ``POST`` (admin-gated via
``require_role``) adds a member by email, finding or creating the ``User``
row as needed; granting the ``owner`` role is further restricted to callers
who are themselves an ``owner``.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select

from ippon.api.authz import OrgCtx, require_role
from ippon.api.deps import DbSession
from ippon.models import OrgMember, OrgMemberRole, User
from ippon.schemas.member import MemberAdd, MemberList, MemberResponse

router = APIRouter(prefix="/orgs/{org}/members", tags=["members"])


@router.get("", response_model=MemberList, summary="List org members")
async def list_members(ctx: OrgCtx, db: DbSession) -> MemberList:
    rows = await db.execute(
        select(User, OrgMember.role)
        .join(OrgMember, OrgMember.user_id == User.id)
        .where(OrgMember.org_id == ctx.org_id)
        .order_by(User.email)
    )
    items = [
        MemberResponse(user_id=u.id, email=u.email, display_name=u.display_name, role=r)
        for u, r in rows.all()
    ]
    return MemberList(items=items, total=len(items))


@router.post(
    "",
    response_model=MemberResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_role(OrgMemberRole.admin))],
    summary="Add a member by email",
)
async def add_member(body: MemberAdd, ctx: OrgCtx, db: DbSession) -> MemberResponse:
    if body.role == OrgMemberRole.owner and ctx.role != OrgMemberRole.owner:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="only an owner can grant owner")
    user = await db.scalar(select(User).where(User.email == body.email))
    if user is None:
        user = User(email=body.email)
        db.add(user)
        await db.flush()
    existing = await db.scalar(
        select(OrgMember).where(OrgMember.org_id == ctx.org_id, OrgMember.user_id == user.id)
    )
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="already a member")
    db.add(OrgMember(org_id=ctx.org_id, user_id=user.id, role=body.role))
    await db.flush()
    return MemberResponse(
        user_id=user.id, email=user.email, display_name=user.display_name, role=body.role
    )
