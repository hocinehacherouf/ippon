"""GitHub webhook receiver.

Routed per connection at ``/webhooks/github/{connection_id}``: the path
identifies which GitHub connection (cloud or Enterprise) the delivery is
for, and verification uses that connection's own webhook secret
(``X-Hub-Signature-256``, HMAC-SHA256). Dedupes by ``X-GitHub-Delivery``.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, status

from ippon.api.deps import DbSession, SettingsDep
from ippon.api.routes.webhooks._common import (
    load_connection_secret,
    parse_payload,
    record_delivery,
)
from ippon.models import SourceProvider, WebhookSource
from ippon.security import verify_hmac_sha256

router = APIRouter(prefix="/webhooks/github", tags=["webhooks"])


@router.post(
    "/{connection_id}",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Receive a GitHub webhook for a specific connection",
)
async def receive_github_webhook(
    connection_id: UUID,
    request: Request,
    session: DbSession,
    settings: SettingsDep,
) -> dict[str, str]:
    conn, secret = await load_connection_secret(
        session,
        connection_id=connection_id,
        provider=SourceProvider.github,
        settings=settings,
    )

    body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256")
    if not signature or not verify_hmac_sha256(signature, body, secret.encode("utf-8")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing X-Hub-Signature-256",
        )

    delivery_id = request.headers.get("X-GitHub-Delivery")
    event_type = request.headers.get("X-GitHub-Event")
    if not delivery_id or not event_type:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="missing X-GitHub-Delivery or X-GitHub-Event",
        )

    try:
        payload = parse_payload(body)
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"invalid JSON: {exc}"
        ) from exc

    _, is_new = await record_delivery(
        session,
        source=WebhookSource.github,
        source_connection_id=conn.id,
        delivery_id=delivery_id,
        event_type=event_type,
        signature=signature,
        payload=payload,
    )
    return {"status": "accepted" if is_new else "duplicate"}
