"""Org + membership routes.

``GET /orgs`` and ``POST /orgs`` are authn-only (no ``require_org_member``):
any authenticated caller can list the orgs they belong to, and creating an
org makes the caller its first member, with the ``owner`` role.

``detail_router`` is mounted under ``/orgs/{org}`` in ``main.py`` (with
``require_org_member`` applied at the mount point) and provides the
org-detail routes: ``GET`` (any member), ``PATCH``/``DELETE`` (owner-gated
via ``require_role``).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select

from ippon.api.authz import OrgCtx, require_role
from ippon.api.deps import CurrentUser, DbSession
from ippon.api.orgs_service import list_memberships
from ippon.models import Org, OrgMember, OrgMemberRole
from ippon.schemas.org import OrgCreate, OrgList, OrgResponse, OrgUpdate

router = APIRouter(prefix="/orgs", tags=["orgs"])
detail_router = APIRouter(prefix="/orgs/{org}", tags=["orgs"])


@router.get("", response_model=OrgList, summary="List the caller's orgs")
async def list_orgs(user: CurrentUser, db: DbSession) -> OrgList:
    mems = await list_memberships(db, user.user_id)
    items = [OrgResponse(id=o.id, slug=o.slug, name=o.name, role=r) for o, r in mems]
    return OrgList(items=items, total=len(items))


@router.post(
    "",
    response_model=OrgResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create an org",
)
async def create_org(body: OrgCreate, user: CurrentUser, db: DbSession) -> OrgResponse:
    if await db.scalar(select(Org).where(Org.slug == body.slug)) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"slug {body.slug!r} already taken")
    org = Org(slug=body.slug, name=body.name)
    db.add(org)
    await db.flush()
    db.add(OrgMember(org_id=org.id, user_id=user.user_id, role=OrgMemberRole.owner))
    await db.flush()
    return OrgResponse(id=org.id, slug=org.slug, name=org.name, role=OrgMemberRole.owner)


@detail_router.get("", response_model=OrgResponse, summary="Get an org")
async def get_org(ctx: OrgCtx, db: DbSession) -> OrgResponse:
    org = await db.get(Org, ctx.org_id)
    assert org is not None  # require_org_member already proved it exists
    return OrgResponse(id=org.id, slug=org.slug, name=org.name, role=ctx.role)


@detail_router.patch(
    "",
    response_model=OrgResponse,
    dependencies=[Depends(require_role(OrgMemberRole.owner))],
    summary="Rename an org",
)
async def update_org(body: OrgUpdate, ctx: OrgCtx, db: DbSession) -> OrgResponse:
    org = await db.get(Org, ctx.org_id)
    assert org is not None
    org.name = body.name
    await db.flush()
    return OrgResponse(id=org.id, slug=org.slug, name=org.name, role=ctx.role)


@detail_router.delete(
    "",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_role(OrgMemberRole.owner))],
    summary="Delete an org",
)
async def delete_org(ctx: OrgCtx, db: DbSession) -> None:
    org = await db.get(Org, ctx.org_id)
    assert org is not None
    await db.delete(org)
