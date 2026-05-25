"""SQLAlchemy engines, session factories, and declarative base.

The API path is async (``async_session_factory``); workers and Alembic are sync
(``sync_session_factory``). Both share the same ``Base`` metadata so models are
defined exactly once.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, MetaData, func
from sqlalchemy.engine import Engine, create_engine
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from ippon.config import Settings, get_settings

# Stable, predictable constraint names so Alembic autogenerate emits readable
# revisions and migrations are reproducible across environments.
NAMING_CONVENTION: dict[str, str] = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Project-wide SQLAlchemy declarative base."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class TimestampMixin:
    """``created_at`` + ``updated_at`` columns with server-side defaults."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


def make_async_engine(settings: Settings | None = None, **kwargs: Any) -> AsyncEngine:
    settings = settings or get_settings()
    return create_async_engine(settings.database_url, **kwargs)


def make_sync_engine(settings: Settings | None = None, **kwargs: Any) -> Engine:
    settings = settings or get_settings()
    return create_engine(settings.database_url, **kwargs)


def make_async_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


def make_sync_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(engine, expire_on_commit=False, class_=Session)


@asynccontextmanager
async def async_session_scope(
    factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncSession]:
    """Async session with commit-on-success, rollback-on-error semantics."""
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


@contextmanager
def sync_session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    """Sync session with commit-on-success, rollback-on-error semantics."""
    with factory() as session:
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
