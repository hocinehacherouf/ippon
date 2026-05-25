"""GitHub webhook receiver.

Verifies ``X-Hub-Signature-256`` against the configured webhook secret and
dedupes by ``X-GitHub-Delivery``. Downstream processing (resolving the event
to a scan policy and enqueuing a scan) lives in a Celery task wired in M5/M6.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status

from ippon.api.deps import DbSession, SettingsDep
from ippon.api.routes.webhooks._common import parse_payload, record_delivery
from ippon.models import WebhookSource
from ippon.security import verify_hmac_sha256

router = APIRouter(prefix="/webhooks/github", tags=["webhooks"])


@router.post(
    "",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Receive a GitHub webhook",
)
async def receive_github_webhook(
    request: Request,
    session: DbSession,
    settings: SettingsDep,
) -> dict[str, str]:
    body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256")
    if not signature or not verify_hmac_sha256(
        signature, body, settings.github_webhook_secret.encode("utf-8")
    ):
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
        delivery_id=delivery_id,
        event_type=event_type,
        signature=signature,
        payload=payload,
    )
    return {"status": "accepted" if is_new else "duplicate"}
