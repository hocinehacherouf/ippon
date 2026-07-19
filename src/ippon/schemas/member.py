"""Pydantic request/response models for the org member API."""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, Field

from ippon.models import OrgMemberRole


class MemberAdd(BaseModel):
    """Request model for adding a member to an organization."""

    email: str = Field(..., min_length=3, max_length=255)
    role: OrgMemberRole


class MemberUpdate(BaseModel):
    """Request model for updating a member's role."""

    role: OrgMemberRole


class MemberResponse(BaseModel):
    """Response model for a single organization member."""

    user_id: UUID
    email: str
    display_name: str | None
    role: OrgMemberRole


class MemberList(BaseModel):
    """Response model for listing organization members."""

    items: list[MemberResponse]
    total: int
