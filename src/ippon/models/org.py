"""Org + OrgMember models."""

from __future__ import annotations

import uuid

from sqlalchemy import Enum as SAEnum
from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from ippon.db import Base, TimestampMixin
from ippon.models._enums import OrgMemberRole


class Org(TimestampMixin, Base):
    __tablename__ = "orgs"

    id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    slug: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)


class OrgMember(TimestampMixin, Base):
    __tablename__ = "org_members"
    __table_args__ = (UniqueConstraint("org_id", "user_id"),)

    id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("orgs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    role: Mapped[OrgMemberRole] = mapped_column(
        SAEnum(OrgMemberRole, name="org_member_role"),
        nullable=False,
        default=OrgMemberRole.member,
    )
