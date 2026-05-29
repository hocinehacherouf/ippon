"""Pydantic request/response models for the source-connection API.

Secrets are never echoed: ``credential`` is write-only (input), and the
per-connection ``webhook_secret`` is returned exactly once — in the
``SourceConnectionCreated`` response on create / rotate. Read endpoints
surface only booleans (``has_credential``, ``webhook_configured``).
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ippon.models import SourceCredentialType, SourceProvider


class SourceConnectionCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255, description="Unique within the org.")
    provider: SourceProvider
    base_url: str | None = Field(
        default=None,
        max_length=512,
        description=(
            "Instance base URL (e.g. https://git.acme.com for GitHub "
            "Enterprise or self-hosted GitLab). Leave empty for the "
            "provider's public cloud (github.com / gitlab.com / dev.azure.com)."
        ),
    )
    credential_type: SourceCredentialType = SourceCredentialType.pat
    credential: str | None = Field(
        default=None,
        description="Raw PAT / token. Required unless credential_type is 'none'. Write-only.",
    )

    @model_validator(mode="after")
    def _check_credential(self) -> SourceConnectionCreate:
        if self.credential_type == SourceCredentialType.none:
            if self.credential:
                raise ValueError("credential must be empty when credential_type is 'none'")
        elif not self.credential:
            raise ValueError(f"credential is required for credential_type '{self.credential_type}'")
        return self


class SourceConnectionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    org_id: UUID
    name: str
    provider: SourceProvider
    credential_type: SourceCredentialType
    base_url: str | None
    has_credential: bool
    webhook_configured: bool
    webhook_url: str
    last_used_at: datetime | None
    created_at: datetime
    updated_at: datetime


class SourceConnectionCreated(SourceConnectionResponse):
    """Returned once on create / rotate — carries the plaintext webhook secret.

    Paste ``webhook_secret`` into the provider's webhook configuration
    (GitHub secret / GitLab token / Azure DevOps basic-auth password). It is
    not retrievable afterwards; rotate to mint a new one.
    """

    webhook_secret: str


class SourceConnectionList(BaseModel):
    items: list[SourceConnectionResponse]
    total: int
