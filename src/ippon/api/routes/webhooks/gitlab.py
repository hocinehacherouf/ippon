"""GitLab webhook receiver.

GitLab uses a plain ``X-Gitlab-Token`` header (not HMAC); the receiver
constant-time-compares it against the configured webhook secret and dedupes
on ``X-Gitlab-Event-UUID``.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status

from ippon.api.deps import DbSession, SettingsDep
from ippon.api.routes.webhooks._common import parse_payload, record_delivery
from ippon.models import WebhookSource
from ippon.security import constant_time_str_eq

router = APIRouter(prefix="/webhooks/gitlab", tags=["webhooks"])


@router.post(
    "",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Receive a GitLab webhook",
)
async def receive_gitlab_webhook(
    request: Request,
    session: DbSession,
    settings: SettingsDep,
) -> dict[str, str]:
    token = request.headers.get("X-Gitlab-Token")
    if not constant_time_str_eq(token or "", settings.gitlab_webhook_secret):
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
        delivery_id=delivery_id,
        event_type=event_type,
        signature=None,
        payload=payload,
    )
    return {"status": "accepted" if is_new else "duplicate"}
