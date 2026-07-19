"""Org membership routes.

Mounted under ``/orgs/{org}/members`` (``require_org_member`` is applied at
the mount point in ``main.py``, same as ``orgs.detail_router``).

``GET`` (any member) lists the org's members. ``POST`` (admin-gated via
``require_role``) adds a member by email, finding or creating the ``User``
row as needed; granting the ``owner`` role is further restricted to callers
who are themselves an ``owner``.

``PATCH``/``DELETE`` (also admin-gated) change a member's role or remove
them. Both are further restricted to callers who are themselves an
``owner`` when the target is (or, for ``PATCH``, would become) an
``owner``, and both refuse to demote/remove the org's last remaining
``owner`` (via :func:`ippon.api.orgs_service.count_owners`).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select

from ippon.api.authz import OrgCtx, require_role
from ippon.api.deps import DbSession
from ippon.api.orgs_service import count_owners
from ippon.models import OrgMember, OrgMemberRole, User
from ippon.schemas.member import MemberAdd, MemberList, MemberResponse, MemberUpdate

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
    email = body.email.strip().lower()
    if body.role == OrgMemberRole.owner and ctx.role != OrgMemberRole.owner:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="only an owner can grant owner")
    user = await db.scalar(select(User).where(User.email == email))
    if user is None:
        user = User(email=email)
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


async def _load_member(db: DbSession, org_id: uuid.UUID, user_id: uuid.UUID) -> OrgMember:
    m = await db.scalar(
        select(OrgMember).where(OrgMember.org_id == org_id, OrgMember.user_id == user_id)
    )
    if m is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="member not found")
    return m


@router.patch(
    "/{user_id}",
    response_model=MemberResponse,
    dependencies=[Depends(require_role(OrgMemberRole.admin))],
    summary="Change a member's role",
)
async def update_member(
    user_id: uuid.UUID, body: MemberUpdate, ctx: OrgCtx, db: DbSession
) -> MemberResponse:
    m = await _load_member(db, ctx.org_id, user_id)
    # touching an owner (as target or as new role) requires owner
    if (
        m.role == OrgMemberRole.owner or body.role == OrgMemberRole.owner
    ) and ctx.role != OrgMemberRole.owner:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, detail="only an owner can change owner roles"
        )
    if (
        m.role == OrgMemberRole.owner
        and body.role != OrgMemberRole.owner
        and await count_owners(db, ctx.org_id) <= 1
    ):
        raise HTTPException(status.HTTP_409_CONFLICT, detail="cannot demote the last owner")
    m.role = body.role
    await db.flush()
    user = await db.get(User, user_id)
    assert user is not None
    return MemberResponse(
        user_id=user.id, email=user.email, display_name=user.display_name, role=m.role
    )


@router.delete(
    "/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_role(OrgMemberRole.admin))],
    summary="Remove a member",
)
async def remove_member(user_id: uuid.UUID, ctx: OrgCtx, db: DbSession) -> None:
    m = await _load_member(db, ctx.org_id, user_id)
    if m.role == OrgMemberRole.owner and ctx.role != OrgMemberRole.owner:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="only an owner can remove an owner")
    if m.role == OrgMemberRole.owner and await count_owners(db, ctx.org_id) <= 1:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="cannot remove the last owner")
    await db.delete(m)
