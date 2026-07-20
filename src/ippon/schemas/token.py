"""Pydantic request/response models for the API-token management API.

The minted secret is never persisted in readable form — only its sha256
digest and a public ``token_prefix`` are stored — so it can only be surfaced
once, in ``ApiTokenCreated`` on creation. Every other response
(``ApiTokenResponse`` / ``ApiTokenList``) carries metadata only.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from ippon.models import OrgMemberRole


class ApiTokenCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255, description="Human-readable label.")
    role: OrgMemberRole = Field(
        ..., description="Role the token authenticates as; capped at the creator's own role."
    )
    expires_at: datetime | None = Field(
        default=None, description="Optional expiry. The token never expires if omitted."
    )


class ApiTokenCreated(BaseModel):
    """Returned once on create — carries the plaintext bearer token.

    ``token`` is not retrievable afterwards; revoke and mint a new one to
    rotate.
    """

    id: UUID
    name: str
    role: OrgMemberRole
    token_prefix: str
    expires_at: datetime | None
    created_at: datetime
    token: str


class ApiTokenResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    role: OrgMemberRole
    token_prefix: str
    last_used_at: datetime | None
    expires_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime


class ApiTokenList(BaseModel):
    items: list[ApiTokenResponse]
    total: int
