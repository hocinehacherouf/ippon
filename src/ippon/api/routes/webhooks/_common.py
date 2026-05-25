"""Shared helpers for inbound webhook routes.

All three providers go through the same dedupe-then-store path. Verification
is provider-specific and stays in the route module.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ippon.models import WebhookDelivery, WebhookSource


async def record_delivery(
    session: AsyncSession,
    *,
    source: WebhookSource,
    delivery_id: str,
    event_type: str,
    signature: str | None,
    payload: dict[str, Any],
) -> tuple[WebhookDelivery, bool]:
    """Insert a webhook delivery row, or return the existing one if duplicate.

    Returns ``(row, is_new)``. ``is_new=False`` means the provider redelivered
    a previously-seen ``delivery_id``; callers should respond with 200 and
    skip downstream work.
    """
    existing = await session.scalar(
        select(WebhookDelivery).where(
            WebhookDelivery.source == source,
            WebhookDelivery.delivery_id == delivery_id,
        )
    )
    if existing is not None:
        return existing, False

    row = WebhookDelivery(
        source=source,
        delivery_id=delivery_id,
        event_type=event_type,
        signature=signature,
        payload=payload,
        received_at=datetime.now(UTC),
    )
    session.add(row)
    await session.flush()
    return row, True


def parse_payload(body: bytes) -> dict[str, Any]:
    """Parse a webhook JSON body; return ``{}`` on empty body."""
    if not body:
        return {}
    parsed = json.loads(body.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("webhook payload must be a JSON object")
    return parsed
