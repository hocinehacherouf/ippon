"""SourceConnection — GitHub/GitLab/AzDO accounts an org has connected.

Multiple connections of the same provider type can coexist in one org
(github.com cloud + a GitHub Enterprise host, several Azure DevOps orgs,
…). Connections are identified by a human ``name`` unique within the org;
``base_url`` is routing metadata used to match a clone URL to a connection.

``credential_blob`` and ``webhook_secret_blob`` hold ciphertext only —
never plaintext PATs or secrets. Both are encrypted with the Fernet cipher
in ``ippon.security``; ``credential_kid`` records the key version that
encrypted the row. Either may be NULL: an anonymous/public connection has
no credential, and a connection has no webhook secret until one is minted.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, LargeBinary, String, UniqueConstraint
from sqlalchemy import Enum as SAEnum
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from ippon.db import Base, TimestampMixin
from ippon.models._enums import SourceCredentialType, SourceProvider


class SourceConnection(TimestampMixin, Base):
    __tablename__ = "source_connections"
    __table_args__ = (UniqueConstraint("org_id", "name"),)

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
    # Ciphertext only — see module docstring. NULL for anonymous connections.
    credential_blob: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    # Encrypted per-connection webhook secret; NULL until one is minted.
    webhook_secret_blob: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    # Key version that encrypted this row's secret(s); NULL when none stored.
    credential_kid: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
