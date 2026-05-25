"""Pydantic models for the findings API."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class Finding(BaseModel):
    """One row from ClickHouse ``findings``."""

    scan_id: UUID
    cve_id: str
    purl: str
    name: str
    version: str
    severity: str
    fix_state: str
    fix_versions: list[str]
    description: str
    cvss_score: float | None
    cvss_vector: str
    matcher: str
    scanned_at: datetime


class FindingPage(BaseModel):
    items: list[Finding]
    total: int
    limit: int
    offset: int
