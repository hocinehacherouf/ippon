"""Current-principal route.

``GET /me`` is authn-only (no ``require_org_member``): any authenticated
caller can see who they are and which orgs they belong to, regardless of
whether they're a member of any particular org.
"""

from __future__ import annotations

from fastapi import APIRouter

from ippon.api.deps import CurrentUser, DbSession
from ippon.api.orgs_service import list_memberships
from ippon.schemas.me import MembershipItem, MeResponse

router = APIRouter(prefix="/me", tags=["me"])


@router.get("", response_model=MeResponse, summary="Current principal + memberships")
async def get_me(user: CurrentUser, db: DbSession) -> MeResponse:
    mems = await list_memberships(db, user.user_id)
    return MeResponse(
        user_id=user.user_id,
        email=user.email,
        display_name=None,
        memberships=[
            MembershipItem(org_id=o.id, org_slug=o.slug, org_name=o.name, role=r) for o, r in mems
        ],
    )
