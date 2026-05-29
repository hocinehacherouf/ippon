"""SourceConnection CRUD.

Lets an operator register multiple connections per provider type — several
GitHub instances (cloud + Enterprise), self-hosted GitLab alongside
gitlab.com, multiple Azure DevOps orgs — each with its own base URL,
encrypted credential, and per-connection webhook secret.

Secrets never leave the server in a readable form except the webhook secret,
which is shown exactly once (on create / rotate) so it can be pasted into the
provider's webhook configuration.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import func, select

from ippon.api._bootstrap import get_or_create_default_org
from ippon.api.deps import CurrentUser, DbSession, SettingsDep
from ippon.config import Settings
from ippon.models import Repository, SourceConnection, SourceCredentialType
from ippon.schemas.source import (
    SourceConnectionCreate,
    SourceConnectionCreated,
    SourceConnectionList,
    SourceConnectionResponse,
)
from ippon.security import encrypt_secret, generate_webhook_secret

router = APIRouter(prefix="/sources", tags=["sources"])

# Provider → URL path segment for the per-connection webhook receiver.
_WEBHOOK_PATH = {
    "github": "github",
    "gitlab": "gitlab",
    "azure_devops": "azure-devops",
}


def _webhook_url(conn: SourceConnection, settings: Settings) -> str:
    base = settings.ippon_public_base_url.rstrip("/")
    segment = _WEBHOOK_PATH[conn.provider.value]
    return f"{base}/webhooks/{segment}/{conn.id}"


def _to_response(conn: SourceConnection, settings: Settings) -> SourceConnectionResponse:
    return SourceConnectionResponse(
        id=conn.id,
        org_id=conn.org_id,
        name=conn.name,
        provider=conn.provider,
        credential_type=conn.credential_type,
        base_url=conn.base_url,
        has_credential=conn.credential_blob is not None,
        webhook_configured=conn.webhook_secret_blob is not None,
        webhook_url=_webhook_url(conn, settings),
        last_used_at=conn.last_used_at,
        created_at=conn.created_at,
        updated_at=conn.updated_at,
    )


@router.post(
    "",
    response_model=SourceConnectionCreated,
    status_code=status.HTTP_201_CREATED,
    summary="Register a source connection.",
)
async def create_source(
    body: SourceConnectionCreate,
    _user: CurrentUser,
    db: DbSession,
    settings: SettingsDep,
) -> SourceConnectionCreated:
    org = await get_or_create_default_org(db)

    # Reject a duplicate name early with a clean 409 (the DB unique constraint
    # is the backstop).
    dup = await db.scalar(
        select(SourceConnection).where(
            SourceConnection.org_id == org.id,
            SourceConnection.name == body.name,
        )
    )
    if dup is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"a connection named {body.name!r} already exists in this org",
        )

    kid: str | None = None
    credential_blob: bytes | None = None
    if body.credential_type != SourceCredentialType.none and body.credential:
        credential_blob, kid = encrypt_secret(body.credential, settings.ippon_secret_key)

    # Mint a per-connection webhook secret up front (returned once below).
    webhook_secret = generate_webhook_secret()
    webhook_blob, secret_kid = encrypt_secret(webhook_secret, settings.ippon_secret_key)
    kid = kid or secret_kid

    conn = SourceConnection(
        org_id=org.id,
        name=body.name,
        provider=body.provider,
        credential_type=body.credential_type,
        base_url=body.base_url,
        credential_blob=credential_blob,
        webhook_secret_blob=webhook_blob,
        credential_kid=kid,
    )
    db.add(conn)
    await db.flush()
    await db.refresh(conn)  # populate server-default created_at/updated_at

    return SourceConnectionCreated(
        **_to_response(conn, settings).model_dump(),
        webhook_secret=webhook_secret,
    )


@router.get("", response_model=SourceConnectionList, summary="List source connections.")
async def list_sources(
    _user: CurrentUser, db: DbSession, settings: SettingsDep
) -> SourceConnectionList:
    org = await get_or_create_default_org(db)
    conns = list(
        await db.scalars(
            select(SourceConnection)
            .where(SourceConnection.org_id == org.id)
            .order_by(SourceConnection.name)
        )
    )
    return SourceConnectionList(
        items=[_to_response(c, settings) for c in conns],
        total=len(conns),
    )


@router.get(
    "/{source_id}", response_model=SourceConnectionResponse, summary="Get a source connection."
)
async def get_source(
    source_id: UUID, _user: CurrentUser, db: DbSession, settings: SettingsDep
) -> SourceConnectionResponse:
    conn = await db.get(SourceConnection, source_id)
    if conn is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="source not found")
    return _to_response(conn, settings)


@router.delete(
    "/{source_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete a source connection."
)
async def delete_source(source_id: UUID, _user: CurrentUser, db: DbSession) -> None:
    conn = await db.get(SourceConnection, source_id)
    if conn is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="source not found")
    repo_count = await db.scalar(
        select(func.count())
        .select_from(Repository)
        .where(Repository.source_connection_id == source_id)
    )
    if repo_count:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"connection has {repo_count} repositories; delete or reassign them first",
        )
    await db.delete(conn)


@router.post(
    "/{source_id}/rotate-webhook-secret",
    response_model=SourceConnectionCreated,
    summary="Mint a fresh webhook secret (invalidates the previous one).",
)
async def rotate_webhook_secret(
    source_id: UUID, _user: CurrentUser, db: DbSession, settings: SettingsDep
) -> SourceConnectionCreated:
    conn = await db.get(SourceConnection, source_id)
    if conn is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="source not found")
    webhook_secret = generate_webhook_secret()
    conn.webhook_secret_blob, conn.credential_kid = encrypt_secret(
        webhook_secret, settings.ippon_secret_key
    )
    await db.flush()
    await db.refresh(conn)  # populate the onupdate updated_at
    return SourceConnectionCreated(
        **_to_response(conn, settings).model_dump(),
        webhook_secret=webhook_secret,
    )
