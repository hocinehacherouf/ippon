"""Get-or-create helpers for the scaffold's default org/source/repo.

Real multi-tenancy (and a real source-connection management surface) lands
post-scaffold. For the demo, every scan resolves to a single ``default`` org
and a placeholder ``default-github`` source connection.
"""

from __future__ import annotations

from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ippon.models import (
    Org,
    Repository,
    SourceConnection,
    SourceCredentialType,
    SourceProvider,
)


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


async def get_or_create_default_source(
    session: AsyncSession, org: Org, provider: SourceProvider
) -> SourceConnection:
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
        credential_type=SourceCredentialType.pat,
        base_url=None,
        credential_blob=b"",  # public-repo scans don't need a credential
        credential_kid="none",
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


async def resolve_scan_target(
    session: AsyncSession, clone_url: str
) -> tuple[Org, SourceConnection, Repository]:
    """Top-level helper: org + source + repo for a clone URL.

    Used by ``POST /scans`` to register-on-first-scan.
    """
    org = await get_or_create_default_org(session)
    provider = _provider_for_host(urlparse(clone_url).hostname or "")
    source = await get_or_create_default_source(session, org, provider)
    repo = await get_or_create_repository(session, org=org, source=source, clone_url=clone_url)
    return org, source, repo
