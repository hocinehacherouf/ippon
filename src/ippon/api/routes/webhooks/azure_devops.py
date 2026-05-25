"""Azure DevOps webhook receiver.

Azure DevOps service-hook subscriptions can be configured with HTTP Basic
auth on outbound calls; the configured ``azure_devops_webhook_secret`` is
the shared password. We dedupe on the payload's ``id`` field, which AzDO
guarantees is unique per delivery.
"""

from __future__ import annotations

import base64
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status

from ippon.api.deps import DbSession, SettingsDep
from ippon.api.routes.webhooks._common import parse_payload, record_delivery
from ippon.models import WebhookSource
from ippon.security import constant_time_str_eq

router = APIRouter(prefix="/webhooks/azure-devops", tags=["webhooks"])

_BASIC_PREFIX = "Basic "


def _verify_basic_auth(header: str | None, expected_secret: str) -> bool:
    if not header or not header.startswith(_BASIC_PREFIX):
        return False
    try:
        raw = base64.b64decode(header[len(_BASIC_PREFIX) :].strip()).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return False
    # AzDO sends ``ippon:<secret>`` (username is whatever you configure in the
    # service-hook UI — we ignore it and only compare the password).
    if ":" not in raw:
        return False
    _, _, supplied = raw.partition(":")
    return constant_time_str_eq(supplied, expected_secret)


@router.post(
    "",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Receive an Azure DevOps webhook",
)
async def receive_azure_devops_webhook(
    request: Request,
    session: DbSession,
    settings: SettingsDep,
) -> dict[str, str]:
    if not _verify_basic_auth(
        request.headers.get("Authorization"), settings.azure_devops_webhook_secret
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing basic auth credentials",
        )

    body = await request.body()
    try:
        payload: dict[str, Any] = parse_payload(body)
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"invalid JSON: {exc}"
        ) from exc

    delivery_id = payload.get("id")
    event_type = payload.get("eventType")
    if not isinstance(delivery_id, str) or not isinstance(event_type, str):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="payload must include string `id` and `eventType` fields",
        )

    _, is_new = await record_delivery(
        session,
        source=WebhookSource.azure_devops,
        delivery_id=delivery_id,
        event_type=event_type,
        signature=None,
        payload=payload,
    )
    return {"status": "accepted" if is_new else "duplicate"}
