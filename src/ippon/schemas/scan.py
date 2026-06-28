"""Pydantic request/response models for the scans API."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from ippon.models import JobRunnerBackend, ScanJobStatus


class ScanRequest(BaseModel):
    repo_url: str = Field(..., description="HTTPS clone URL.")
    ref: str = Field(default="HEAD", description="Branch, tag, or commit sha.")
    source_connection_id: UUID | None = Field(
        default=None,
        description=(
            "Explicit source connection to scan under. When omitted, the "
            "connection is matched by the clone URL host; if several "
            "connections share that host the request is rejected, asking for "
            "an explicit id."
        ),
    )


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    org_id: UUID
    repository_id: UUID
    status: ScanJobStatus
    backend: JobRunnerBackend
    requested_ref: str
    resolved_commit_sha: str | None
    syft_version: str | None
    grype_version: str | None
    grype_db_version: str | None
    sbom_object_key: str | None
    sbom_sha256: str | None
    queued_at: datetime | None
    started_at: datetime | None
    finished_at: datetime | None
    duration_seconds: float | None
    error_message: str | None
    attempt: int


class CallbackPayload(BaseModel):
    """Wire shape of the reporter → API callback."""

    scan_id: UUID
    status: str  # 'succeeded' | 'failed'
    commit_sha: str | None = None
    object_key: str | None = None
    sbom_sha256: str | None = None
    sbom_size_bytes: int | None = None
    syft_version: str | None = None
    grype_version: str | None = None
    grype_db_version: str | None = None
    dependency_count: int = 0
    finding_count: int = 0
    secret_finding_count: int = 0
    verified_secret_count: int = 0
    severity_counts: dict[str, int] = Field(default_factory=dict)
    failed_step: str | None = None
    error_message: str | None = None
    finished_at: datetime
