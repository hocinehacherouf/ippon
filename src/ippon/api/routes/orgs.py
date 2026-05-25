"""Org + membership routes — placeholders."""

from __future__ import annotations

from fastapi import APIRouter, status

from ippon.api.deps import CurrentUser

router = APIRouter(prefix="/orgs", tags=["orgs"])


@router.get("", status_code=status.HTTP_501_NOT_IMPLEMENTED, summary="List orgs")
async def list_orgs(_: CurrentUser) -> dict[str, str]:
    return {"status": "not_implemented"}


@router.post("", status_code=status.HTTP_501_NOT_IMPLEMENTED, summary="Create org")
async def create_org(_: CurrentUser) -> dict[str, str]:
    return {"status": "not_implemented"}


@router.get(
    "/{org_id}",
    status_code=status.HTTP_501_NOT_IMPLEMENTED,
    summary="Get org",
)
async def get_org(org_id: str, _: CurrentUser) -> dict[str, str]:
    return {"status": "not_implemented", "org_id": org_id}
