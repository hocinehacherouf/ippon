"""Pydantic models for the secret-findings API."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class SecretFinding(BaseModel):
    """One row from ClickHouse ``secret_findings`` (redacted)."""

    scan_id: UUID
    rule_id: str
    description: str
    file: str
    start_line: int
    end_line: int
    match: str
    fingerprint: str
    author: str
    email: str
    committed_at: datetime | None
    tags: list[str]
    verified: bool
    validation_status: str
    is_historical: bool
    scanned_at: datetime


class SecretFindingPage(BaseModel):
    items: list[SecretFinding]
    total: int
    limit: int
    offset: int
