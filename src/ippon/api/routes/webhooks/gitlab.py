"""GitLab webhook receiver.

Routed per connection at ``/webhooks/gitlab/{connection_id}``. GitLab uses a
plain ``X-Gitlab-Token`` header (not HMAC); the receiver constant-time-compares
it against that connection's webhook secret and dedupes on
``X-Gitlab-Event-UUID``.
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
from ippon.security import constant_time_str_eq

router = APIRouter(prefix="/webhooks/gitlab", tags=["webhooks"])


@router.post(
    "/{connection_id}",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Receive a GitLab webhook for a specific connection",
)
async def receive_gitlab_webhook(
    connection_id: UUID,
    request: Request,
    session: DbSession,
    settings: SettingsDep,
) -> dict[str, str]:
    conn, secret = await load_connection_secret(
        session,
        connection_id=connection_id,
        provider=SourceProvider.gitlab,
        settings=settings,
    )

    token = request.headers.get("X-Gitlab-Token")
    if not constant_time_str_eq(token or "", secret):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing X-Gitlab-Token",
        )

    delivery_id = request.headers.get("X-Gitlab-Event-UUID")
    event_type = request.headers.get("X-Gitlab-Event")
    if not delivery_id or not event_type:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="missing X-Gitlab-Event-UUID or X-Gitlab-Event",
        )

    body = await request.body()
    try:
        payload = parse_payload(body)
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"invalid JSON: {exc}"
        ) from exc

    _, is_new = await record_delivery(
        session,
        source=WebhookSource.gitlab,
        source_connection_id=conn.id,
        delivery_id=delivery_id,
        event_type=event_type,
        signature=None,
        payload=payload,
    )
    return {"status": "accepted" if is_new else "duplicate"}
