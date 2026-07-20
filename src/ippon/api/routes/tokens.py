"""API-token management routes.

Mounted under ``/orgs/{org}/tokens`` (``require_org_member`` is applied at
the mount point in ``main.py``, same as ``members.router``).

``POST`` (admin-gated via ``require_role``) mints a token; the caller may not
grant a role above their own (``role_at_least(ctx.role, body.role)``). The
plaintext token is shown exactly once, in the create response — only its
prefix and a sha256 digest are persisted.

``GET`` (any member) lists this org's tokens as metadata only — no secret or
digest ever leaves the server after creation.

``DELETE`` (admin-gated) soft-revokes a token by stamping ``revoked_at``;
404s if the token doesn't exist in this org.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select

from ippon.api.authz import OrgCtx, require_role, role_at_least
from ippon.api.deps import DbSession
from ippon.models import ApiToken, OrgMemberRole
from ippon.schemas.token import ApiTokenCreate, ApiTokenCreated, ApiTokenList, ApiTokenResponse
from ippon.security import mint_api_token

router = APIRouter(prefix="/orgs/{org}/tokens", tags=["tokens"])


def _to_response(t: ApiToken) -> ApiTokenResponse:
    return ApiTokenResponse(
        id=t.id,
        name=t.name,
        role=t.role,
        token_prefix=t.token_prefix,
        last_used_at=t.last_used_at,
        expires_at=t.expires_at,
        revoked_at=t.revoked_at,
        created_at=t.created_at,
    )


@router.post(
    "",
    response_model=ApiTokenCreated,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_role(OrgMemberRole.admin))],
    summary="Mint an API token",
)
async def create_token(body: ApiTokenCreate, ctx: OrgCtx, db: DbSession) -> ApiTokenCreated:
    if not role_at_least(ctx.role, body.role):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="cannot grant a role above your own")
    full, prefix, secret_hash = mint_api_token()
    tok = ApiToken(
        org_id=ctx.org_id,
        created_by_user_id=ctx.principal.user_id,
        name=body.name,
        role=body.role,
        token_prefix=prefix,
        token_sha256=secret_hash,
        expires_at=body.expires_at,
    )
    db.add(tok)
    await db.flush()
    await db.refresh(tok)
    return ApiTokenCreated(
        id=tok.id,
        name=tok.name,
        role=tok.role,
        token_prefix=tok.token_prefix,
        expires_at=tok.expires_at,
        created_at=tok.created_at,
        token=full,
    )


@router.get("", response_model=ApiTokenList, summary="List API tokens (no secrets)")
async def list_tokens(ctx: OrgCtx, db: DbSession) -> ApiTokenList:
    rows = list(
        await db.scalars(
            select(ApiToken)
            .where(ApiToken.org_id == ctx.org_id)
            .order_by(ApiToken.created_at.desc())
        )
    )
    return ApiTokenList(items=[_to_response(t) for t in rows], total=len(rows))


@router.delete(
    "/{token_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_role(OrgMemberRole.admin))],
    summary="Revoke an API token",
)
async def revoke_token(token_id: uuid.UUID, ctx: OrgCtx, db: DbSession) -> None:
    tok = await db.scalar(
        select(ApiToken).where(ApiToken.id == token_id, ApiToken.org_id == ctx.org_id)
    )
    if tok is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="token not found")
    if tok.revoked_at is None:
        tok.revoked_at = datetime.now(UTC)
