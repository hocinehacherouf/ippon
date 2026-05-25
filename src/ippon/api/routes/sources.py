"""SourceConnection routes — placeholders."""

from __future__ import annotations

from fastapi import APIRouter, status

from ippon.api.deps import CurrentUser

router = APIRouter(prefix="/sources", tags=["sources"])


@router.get("", status_code=status.HTTP_501_NOT_IMPLEMENTED, summary="List source connections")
async def list_sources(_: CurrentUser) -> dict[str, str]:
    return {"status": "not_implemented"}


@router.post("", status_code=status.HTTP_501_NOT_IMPLEMENTED, summary="Register a source")
async def create_source(_: CurrentUser) -> dict[str, str]:
    return {"status": "not_implemented"}


@router.delete(
    "/{source_id}",
    status_code=status.HTTP_501_NOT_IMPLEMENTED,
    summary="Delete a source",
)
async def delete_source(source_id: str, _: CurrentUser) -> dict[str, str]:
    return {"status": "not_implemented", "source_id": source_id}
