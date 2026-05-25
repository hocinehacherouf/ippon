"""WebhookDelivery — every inbound webhook, dedup'd by provider delivery id.

The raw payload is stored so the API can replay or audit deliveries; downstream
processing happens out-of-band in a Celery task that updates ``processed_at``
and ``error``.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy import Enum as SAEnum
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from ippon.db import Base, TimestampMixin
from ippon.models._enums import WebhookSource


class WebhookDelivery(TimestampMixin, Base):
    __tablename__ = "webhook_deliveries"
    # Provider delivery IDs are unique per source — dedupe on that pair.
    __table_args__ = (UniqueConstraint("source", "delivery_id"),)

    id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    source: Mapped[WebhookSource] = mapped_column(
        SAEnum(WebhookSource, name="webhook_source"), nullable=False, index=True
    )
    # GitHub: X-GitHub-Delivery; GitLab: X-Gitlab-Event-UUID; AzDO: id field.
    delivery_id: Mapped[str] = mapped_column(String(128), nullable=False)
    # GitHub: X-GitHub-Event; GitLab: X-Gitlab-Event; AzDO: eventType.
    event_type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)

    # The source connection this delivery resolves to; nullable because the
    # API may receive an unknown installation/project that doesn't map yet.
    source_connection_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("source_connections.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Raw HTTP request shape for audit/replay.
    signature: Mapped[str | None] = mapped_column(String(255), nullable=True)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)  # type: ignore[type-arg]

    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(String(1024), nullable=True)
