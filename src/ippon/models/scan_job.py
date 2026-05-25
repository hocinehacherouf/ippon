"""ScanJob — one row per scan attempt; the orchestration anchor.

The row is created the moment a scan is enqueued, before the JobRunner has
even submitted anything. The HMAC secret is generated here and embedded into
the scan-job container's env so the reporter can sign its callback.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy import Enum as SAEnum
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from ippon.db import Base, TimestampMixin
from ippon.models._enums import JobRunnerBackend, ScanJobStatus, ScanTrigger


class ScanJob(TimestampMixin, Base):
    __tablename__ = "scan_jobs"

    id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("orgs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    repository_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("repositories.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    status: Mapped[ScanJobStatus] = mapped_column(
        SAEnum(ScanJobStatus, name="scan_job_status"),
        nullable=False,
        default=ScanJobStatus.pending,
        index=True,
    )
    trigger: Mapped[ScanTrigger] = mapped_column(
        SAEnum(ScanTrigger, name="scan_trigger"),
        nullable=False,
        default=ScanTrigger.manual,
    )
    backend: Mapped[JobRunnerBackend] = mapped_column(
        SAEnum(JobRunnerBackend, name="job_runner_backend"),
        nullable=False,
        default=JobRunnerBackend.docker,
    )
    # Opaque handle returned by the JobRunner (Docker container/network/volume
    # group id, K8s Job name, etc.) — used by status/cleanup.
    backend_handle: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Git ref the user asked us to scan ("main", a tag, or a commit sha).
    requested_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    # Commit sha resolved at clone time; populated by the reporter callback.
    resolved_commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Reporter callback verification — HMAC-SHA256 with this per-job secret.
    # Generated at submit time; never reused across scans.
    callback_secret: Mapped[str] = mapped_column(String(128), nullable=False)

    # Tool versions and artifact references, populated on success.
    syft_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    grype_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    grype_db_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    sbom_object_key: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    sbom_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Lifecycle timestamps.
    queued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)

    # On failure.
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
