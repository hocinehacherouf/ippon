"""FastAPI dependency providers.

The app factory wires concrete clients onto ``app.state`` at startup; these
dependencies pull them off and yield per-request handles. Tests can replace
the underlying ``app.state`` objects to inject fakes.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Annotated, cast

from clickhouse_connect.driver import Client as CHClient
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ippon.config import Settings
from ippon.db import async_session_scope
from ippon.security import Principal, authenticate_dev_token

bearer_scheme = HTTPBearer(auto_error=False)


def get_settings_dep(request: Request) -> Settings:
    return cast(Settings, request.app.state.settings)


def get_session_factory(request: Request) -> async_sessionmaker[AsyncSession]:
    return cast(async_sessionmaker[AsyncSession], request.app.state.session_factory)


def get_redis(request: Request) -> Redis:
    return cast(Redis, request.app.state.redis)


def get_ch_client(request: Request) -> CHClient:
    return cast(CHClient, request.app.state.ch_client)


async def get_db(
    factory: Annotated[async_sessionmaker[AsyncSession], Depends(get_session_factory)],
) -> AsyncIterator[AsyncSession]:
    """Per-request async DB session with commit-on-success semantics."""
    async with async_session_scope(factory) as session:
        yield session


async def require_user(
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    settings: Annotated[Settings, Depends(get_settings_dep)],
) -> Principal:
    if creds is None or creds.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing or malformed Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    principal = authenticate_dev_token(creds.credentials, settings.ippon_dev_token)
    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return principal


# Type aliases for cleaner route signatures.
CurrentUser = Annotated[Principal, Depends(require_user)]
DbSession = Annotated[AsyncSession, Depends(get_db)]
SettingsDep = Annotated[Settings, Depends(get_settings_dep)]
RedisDep = Annotated[Redis, Depends(get_redis)]
CHDep = Annotated[CHClient, Depends(get_ch_client)]
