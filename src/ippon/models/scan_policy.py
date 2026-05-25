"""ScanPolicy — when and how to scan a repo.

A policy attaches to either an Org (defaults) or a specific Repository (override).
"""

from __future__ import annotations

import uuid

from sqlalchemy import Boolean, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from ippon.db import Base, TimestampMixin


class ScanPolicy(TimestampMixin, Base):
    __tablename__ = "scan_policies"

    id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("orgs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    repository_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("repositories.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    scan_on_push: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    scan_on_pull_request: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Cron expression; None = no scheduled scans.
    cron_schedule: Mapped[str | None] = mapped_column(String(64), nullable=True)
    max_runtime_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=900)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
