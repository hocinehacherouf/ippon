"""Auth routes — OIDC flow placeholders.

For the scaffold, callers authenticate with a bearer token set via
``IPPON_DEV_TOKEN``; there is no token-issuing endpoint to call yet.
"""

from __future__ import annotations

from fastapi import APIRouter, status

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get(
    "/login",
    status_code=status.HTTP_501_NOT_IMPLEMENTED,
    summary="Begin OIDC login (not implemented)",
)
async def login() -> dict[str, str]:
    return {"status": "not_implemented", "message": "OIDC login lands post-scaffold"}


@router.get(
    "/callback",
    status_code=status.HTTP_501_NOT_IMPLEMENTED,
    summary="OIDC callback (not implemented)",
)
async def callback() -> dict[str, str]:
    return {"status": "not_implemented", "message": "OIDC callback lands post-scaffold"}
