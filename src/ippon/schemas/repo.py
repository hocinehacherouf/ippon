"""Pydantic models for the repos API."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from ippon.models import ScanJobStatus


class RepositoryListItem(BaseModel):
    """A repository plus a thin summary of its most recent scan."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    org_id: UUID
    full_name: str
    clone_url: str
    default_branch: str
    is_archived: bool
    last_scanned_at: datetime | None

    # Joined from the latest scan_jobs row, if any.
    last_scan_id: UUID | None = None
    last_scan_status: ScanJobStatus | None = None
    last_scan_finished_at: datetime | None = None
    last_scan_duration_seconds: float | None = None


class RepositoryList(BaseModel):
    items: list[RepositoryListItem]
    total: int
