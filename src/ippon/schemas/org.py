"""Pydantic request/response models for the org API."""

from __future__ import annotations

import re
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from ippon.models import OrgMemberRole

_SLUG = re.compile(r"^[a-z0-9-]{1,255}\Z")


class OrgCreate(BaseModel):
    """Request model for creating an organization."""

    name: str = Field(..., min_length=1, max_length=255)
    slug: str = Field(..., min_length=1, max_length=255)

    @field_validator("slug")
    @classmethod
    def _valid_slug(cls, v: str) -> str:
        if not _SLUG.match(v):
            raise ValueError("slug must match ^[a-z0-9-]{1,255}$")
        return v


class OrgUpdate(BaseModel):
    """Request model for updating an organization."""

    name: str = Field(..., min_length=1, max_length=255)


class OrgResponse(BaseModel):
    """Response model for a single organization."""

    id: UUID
    slug: str
    name: str
    role: OrgMemberRole


class OrgList(BaseModel):
    """Response model for listing organizations."""

    items: list[OrgResponse]
    total: int
