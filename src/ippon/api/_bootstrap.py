"""Scan-target resolution: map a clone URL (or an explicit connection id) to
an org + source connection + repository, registering rows on first sight.

Resolution order in :func:`resolve_scan_target`:

1. **Explicit** — if ``source_connection_id`` is given, use that connection
   (must belong to the org), else :class:`ConnectionNotFoundError`.
2. **Host match** — otherwise match the clone URL's host against each
   connection's host (its ``base_url`` host, or the provider's cloud host
   when ``base_url`` is NULL). Exactly one match → use it; several →
   :class:`AmbiguousConnectionError` (caller asks for an explicit id).
3. **Anonymous fallback** — no match → a ``default-{provider}`` connection
   with ``credential_type=none`` and no stored secret, so zero-config
   public-repo scans keep working.

Multi-tenancy is still single-org for the scaffold (one ``default`` org).
"""

from __future__ import annotations

from urllib.parse import urlparse
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ippon.models import (
    Org,
    Repository,
    SourceConnection,
    SourceCredentialType,
    SourceProvider,
)

# Provider public-cloud hosts, used when a connection has no explicit base_url.
_CLOUD_HOST = {
    SourceProvider.github: "github.com",
    SourceProvider.gitlab: "gitlab.com",
    SourceProvider.azure_devops: "dev.azure.com",
}


class ResolutionError(Exception):
    """Base class for scan-target resolution failures (routes map to HTTP)."""


class ConnectionNotFoundError(ResolutionError):
    """An explicit source_connection_id didn't resolve within the org."""


class AmbiguousConnectionError(ResolutionError):
    """Several connections match the clone host; an explicit id is required."""


async def get_or_create_default_org(session: AsyncSession) -> Org:
    org = await session.scalar(select(Org).where(Org.slug == "default"))
    if org is not None:
        return org
    org = Org(slug="default", name="Default")
    session.add(org)
    await session.flush()
    return org


def _provider_for_host(host: str) -> SourceProvider:
    h = host.lower()
    if "gitlab" in h:
        return SourceProvider.gitlab
    if "dev.azure.com" in h or "visualstudio.com" in h:
        return SourceProvider.azure_devops
    return SourceProvider.github


def _normalize_host(host: str | None) -> str:
    return (host or "").lower().strip()


def _connection_host(conn: SourceConnection) -> str:
    """The host a connection serves: its base_url host, or the cloud host."""
    if conn.base_url:
        return _normalize_host(urlparse(conn.base_url).hostname)
    return _CLOUD_HOST[conn.provider]


async def get_or_create_default_source(
    session: AsyncSession, org: Org, provider: SourceProvider
) -> SourceConnection:
    """The anonymous fallback connection for a provider's public cloud."""
    name = f"default-{provider.value}"
    existing = await session.scalar(
        select(SourceConnection).where(
            SourceConnection.org_id == org.id,
            SourceConnection.name == name,
        )
    )
    if existing is not None:
        return existing
    src = SourceConnection(
        org_id=org.id,
        name=name,
        provider=provider,
        credential_type=SourceCredentialType.none,
        base_url=None,
        credential_blob=None,  # public-repo scans need no credential
        webhook_secret_blob=None,
        credential_kid=None,
    )
    session.add(src)
    await session.flush()
    return src


def _derive_full_name(clone_url: str) -> str:
    """Derive ``owner/repo`` from a clone URL (best-effort)."""
    parsed = urlparse(clone_url)
    path = parsed.path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    return path or clone_url


async def get_or_create_repository(
    session: AsyncSession, *, org: Org, source: SourceConnection, clone_url: str
) -> Repository:
    full_name = _derive_full_name(clone_url)
    existing = await session.scalar(
        select(Repository).where(Repository.org_id == org.id, Repository.full_name == full_name)
    )
    if existing is not None:
        return existing
    repo = Repository(
        org_id=org.id,
        source_connection_id=source.id,
        remote_id=full_name,  # no provider API call yet — use full_name as a stand-in
        full_name=full_name,
        clone_url=clone_url,
        default_branch="main",
    )
    session.add(repo)
    await session.flush()
    return repo


async def _resolve_source(
    session: AsyncSession,
    org: Org,
    clone_url: str,
    source_connection_id: UUID | None,
) -> SourceConnection:
    # 1. Explicit selection wins.
    if source_connection_id is not None:
        conn = await session.scalar(
            select(SourceConnection).where(
                SourceConnection.id == source_connection_id,
                SourceConnection.org_id == org.id,
            )
        )
        if conn is None:
            raise ConnectionNotFoundError(str(source_connection_id))
        return conn

    # 2. Match configured connections by clone host.
    host = _normalize_host(urlparse(clone_url).hostname)
    connections = list(
        await session.scalars(select(SourceConnection).where(SourceConnection.org_id == org.id))
    )
    matches = [c for c in connections if _connection_host(c) == host and host]
    # Don't let the anonymous fallback connections count as real matches.
    real_matches = [c for c in matches if not c.name.startswith("default-")]
    if len(real_matches) == 1:
        return real_matches[0]
    if len(real_matches) > 1:
        raise AmbiguousConnectionError(host)
    if len(matches) == 1:
        return matches[0]

    # 3. Anonymous fallback for the inferred provider.
    provider = _provider_for_host(host)
    return await get_or_create_default_source(session, org, provider)


async def resolve_scan_target(
    session: AsyncSession,
    clone_url: str,
    *,
    source_connection_id: UUID | None = None,
) -> tuple[Org, SourceConnection, Repository]:
    """org + source + repo for a clone URL. Used by ``POST /scans``.

    Raises :class:`ConnectionNotFoundError` or :class:`AmbiguousConnectionError` —
    the route translates these to 404 / 409 respectively.
    """
    org = await get_or_create_default_org(session)
    source = await _resolve_source(session, org, clone_url, source_connection_id)
    repo = await get_or_create_repository(session, org=org, source=source, clone_url=clone_url)
    return org, source, repo
