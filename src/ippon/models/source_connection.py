"""SourceConnection — GitHub/GitLab/AzDO accounts an org has connected.

``credential_blob`` is envelope-encrypted by ``security.py``; the bytes here
are ciphertext, never plaintext PAT. ``credential_kid`` identifies the
encryption key for future rotation.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, LargeBinary, String
from sqlalchemy import Enum as SAEnum
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from ippon.db import Base, TimestampMixin
from ippon.models._enums import SourceCredentialType, SourceProvider


class SourceConnection(TimestampMixin, Base):
    __tablename__ = "source_connections"

    id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("orgs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    provider: Mapped[SourceProvider] = mapped_column(
        SAEnum(SourceProvider, name="source_provider"), nullable=False, index=True
    )
    credential_type: Mapped[SourceCredentialType] = mapped_column(
        SAEnum(SourceCredentialType, name="source_credential_type"),
        nullable=False,
    )
    # https://api.github.com / https://gitlab.example.com / https://dev.azure.com/<org>
    base_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    # Ciphertext only — see module docstring.
    credential_blob: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    credential_kid: Mapped[str] = mapped_column(String(64), nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
