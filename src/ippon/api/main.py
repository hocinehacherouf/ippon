"""FastAPI app factory.

Construct with :func:`create_app` (for tests) or import the module-level
``app`` (for uvicorn). The factory wires:

- DB engine + async session factory (Postgres via psycopg v3)
- Async Valkey client (used as cache + Celery broker probe)
- Sync ClickHouse client (used in the readiness check)
- CORS, request-ID, structured error handlers
- Routers under tagged prefixes
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any

import redis.asyncio as redis
from fastapi import FastAPI, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from ippon import __version__
from ippon.api.routes import admin as admin_routes
from ippon.api.routes import auth as auth_routes
from ippon.api.routes import health as health_routes
from ippon.api.routes import internal as internal_routes
from ippon.api.routes import orgs as orgs_routes
from ippon.api.routes import repos as repos_routes
from ippon.api.routes import scans as scans_routes
from ippon.api.routes import sources as sources_routes
from ippon.api.routes.webhooks import azure_devops as azdo_webhooks
from ippon.api.routes.webhooks import github as github_webhooks
from ippon.api.routes.webhooks import gitlab as gitlab_webhooks
from ippon.clickhouse import make_sync_client
from ippon.config import Settings, get_settings
from ippon.db import make_async_engine, make_async_session_factory

OPENAPI_TAGS = [
    {"name": "health", "description": "Liveness and readiness probes."},
    {"name": "auth", "description": "Bearer-token auth (dev) / OIDC (planned)."},
    {"name": "orgs", "description": "Organizations and membership."},
    {"name": "sources", "description": "Source-provider connections (GitHub/GitLab/AzDO)."},
    {"name": "repos", "description": "Registered repositories."},
    {"name": "scans", "description": "Scan jobs and findings."},
    {"name": "admin", "description": "Operator smoke tests (Celery ping, etc.)."},
    {"name": "internal", "description": "Machine-to-machine callbacks (HMAC-signed)."},
    {"name": "webhooks", "description": "Inbound provider webhooks."},
]


def _make_lifespan(settings: Settings) -> Any:
    """Build a lifespan context manager bound to ``settings``.

    Typed as ``Any`` because FastAPI's lifespan parameter accepts the
    decorated form of ``@asynccontextmanager`` whose exact signature varies
    across Starlette versions; we don't gain anything by trying to nail it
    down here.
    """

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine = make_async_engine(settings)
        app.state.settings = settings
        app.state.engine = engine
        app.state.session_factory = make_async_session_factory(engine)
        app.state.redis = redis.Redis.from_url(settings.valkey_url, decode_responses=True)
        app.state.ch_client = make_sync_client(settings)
        try:
            yield
        finally:
            await app.state.redis.aclose()
            app.state.ch_client.close()
            await engine.dispose()

    return lifespan


def _install_middleware(app: FastAPI, settings: Settings) -> None:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Request-Id"],
    )

    @app.middleware("http")
    async def request_id_middleware(
        request: Request,
        call_next: Callable[[Request], Awaitable[JSONResponse]],
    ) -> JSONResponse:
        rid = request.headers.get("X-Request-Id") or str(uuid.uuid4())
        request.state.request_id = rid
        response = await call_next(request)
        response.headers["X-Request-Id"] = rid
        return response


def _install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": exc.status_code,
                    "message": exc.detail,
                    "request_id": getattr(request.state, "request_id", None),
                }
            },
            headers=getattr(exc, "headers", None) or {},
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": {
                    "code": status.HTTP_422_UNPROCESSABLE_ENTITY,
                    "message": "validation failed",
                    # jsonable_encoder flattens any non-serializable bits
                    # (e.g. a validator-raised ValueError carried in ``ctx``).
                    "details": jsonable_encoder(exc.errors()),
                    "request_id": getattr(request.state, "request_id", None),
                }
            },
        )


def _install_routes(app: FastAPI) -> None:
    app.include_router(health_routes.router)
    app.include_router(auth_routes.router)
    app.include_router(orgs_routes.router)
    app.include_router(sources_routes.router)
    app.include_router(repos_routes.router)
    app.include_router(scans_routes.router)
    app.include_router(admin_routes.router)
    app.include_router(internal_routes.router)
    app.include_router(github_webhooks.router)
    app.include_router(gitlab_webhooks.router)
    app.include_router(azdo_webhooks.router)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    app = FastAPI(
        title="ippon",
        description=(
            "Open-source SBOM generator and CVE scanner. Watches GitHub, "
            "GitLab, and Azure DevOps repositories; launches per-scan "
            "ephemeral jobs; serves dependency and finding queries."
        ),
        version=__version__,
        openapi_tags=OPENAPI_TAGS,
        lifespan=_make_lifespan(settings),
    )
    # Cache settings on state so routes/deps can access them without a fresh
    # ``get_settings()`` call (which would re-read .env).
    app.state.settings = settings
    _install_middleware(app, settings)
    _install_error_handlers(app)
    _install_routes(app)
    return app


app = create_app()
