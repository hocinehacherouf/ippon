"""Org + membership routes.

``GET /orgs`` and ``POST /orgs`` are authn-only (no ``require_org_member``):
any authenticated caller can list the orgs they belong to, and creating an
org makes the caller its first member, with the ``owner`` role.
``GET /orgs/{org_id}`` remains a 501 stub — Task 5 replaces it with the real
org-detail route.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select

from ippon.api.deps import CurrentUser, DbSession
from ippon.api.orgs_service import list_memberships
from ippon.models import Org, OrgMember, OrgMemberRole
from ippon.schemas.org import OrgCreate, OrgList, OrgResponse

router = APIRouter(prefix="/orgs", tags=["orgs"])


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


@router.get(
    "/{org_id}",
    status_code=status.HTTP_501_NOT_IMPLEMENTED,
    summary="Get org",
)
async def get_org(org_id: str, _: CurrentUser) -> dict[str, str]:
    return {"status": "not_implemented", "org_id": org_id}
