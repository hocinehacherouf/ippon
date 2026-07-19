"""Pydantic request/response models for the current user /me endpoint."""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel

from ippon.models import OrgMemberRole


class MembershipItem(BaseModel):
    """Response model for a single user membership."""

    org_id: UUID
    org_slug: str
    org_name: str
    role: OrgMemberRole


class MeResponse(BaseModel):
    """Response model for the current user."""

    user_id: UUID
    email: str | None
    display_name: str | None
    memberships: list[MembershipItem]
