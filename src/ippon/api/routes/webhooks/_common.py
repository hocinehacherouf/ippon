"""Shared helpers for inbound webhook routes.

All three providers go through the same load-connection → verify →
dedupe-then-store path. Connection lookup + signature verification live in
``_connection`` / the per-provider route modules; this module owns the
dedupe-and-store step.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ippon.config import Settings
from ippon.models import SourceConnection, SourceProvider, WebhookDelivery, WebhookSource
from ippon.security import CredentialDecryptionError, decrypt_secret


async def load_connection_secret(
    session: AsyncSession,
    *,
    connection_id: UUID,
    provider: SourceProvider,
    settings: Settings,
) -> tuple[SourceConnection, str]:
    """Load a connection by id and return it plus its decrypted webhook secret.

    Raises 404 if the connection is unknown, 400 if it belongs to a different
    provider, and 401 if it has no webhook secret configured or the stored
    secret can't be decrypted (treated as not-configured to avoid leaking
    crypto state to callers).
    """
    conn = await session.get(SourceConnection, connection_id)
    if conn is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="unknown source connection"
        )
    if conn.provider != provider:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"connection is a {conn.provider.value} source, not {provider.value}",
        )
    if conn.webhook_secret_blob is None or conn.credential_kid is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="connection has no webhook secret configured",
        )
    try:
        secret = decrypt_secret(
            conn.webhook_secret_blob, conn.credential_kid, settings.ippon_secret_key
        )
    except CredentialDecryptionError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="connection webhook secret could not be decrypted",
        ) from exc
    return conn, secret


async def record_delivery(
    session: AsyncSession,
    *,
    source: WebhookSource,
    source_connection_id: UUID,
    delivery_id: str,
    event_type: str,
    signature: str | None,
    payload: dict[str, Any],
) -> tuple[WebhookDelivery, bool]:
    """Insert a webhook delivery row, or return the existing one if duplicate.

    Dedup key is ``(source, delivery_id)`` — provider delivery ids are
    globally unique per provider. Returns ``(row, is_new)``; ``is_new=False``
    means a redelivery the caller should ack without reprocessing.
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
        source_connection_id=source_connection_id,
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
