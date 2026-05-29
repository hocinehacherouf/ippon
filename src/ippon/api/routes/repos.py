"""Repository routes."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import and_, func, select
from sqlalchemy.orm import aliased

from ippon.api.deps import CurrentUser, DbSession
from ippon.models import Repository, ScanJob
from ippon.schemas.repo import RepositoryList, RepositoryListItem

router = APIRouter(prefix="/repos", tags=["repos"])


@router.get(
    "",
    response_model=RepositoryList,
    summary="List repositories with their most recent scan's status.",
)
async def list_repos(_: CurrentUser, db: DbSession) -> RepositoryList:
    # Subquery: latest scan_jobs.created_at per repository.
    latest = (
        select(
            ScanJob.repository_id.label("repo_id"),
            func.max(ScanJob.created_at).label("created_at"),
        )
        .group_by(ScanJob.repository_id)
        .subquery()
    )

    sj = aliased(ScanJob)
    stmt = (
        select(Repository, sj)
        .outerjoin(latest, latest.c.repo_id == Repository.id)
        .outerjoin(
            sj,
            and_(
                sj.repository_id == Repository.id,
                sj.created_at == latest.c.created_at,
            ),
        )
        .order_by(Repository.full_name)
    )
    rows = (await db.execute(stmt)).all()

    items = [
        RepositoryListItem(
            id=repo.id,
            org_id=repo.org_id,
            source_connection_id=repo.source_connection_id,
            full_name=repo.full_name,
            clone_url=repo.clone_url,
            default_branch=repo.default_branch,
            is_archived=repo.is_archived,
            last_scanned_at=repo.last_scanned_at,
            last_scan_id=scan.id if scan else None,
            last_scan_status=scan.status if scan else None,
            last_scan_finished_at=scan.finished_at if scan else None,
            last_scan_duration_seconds=scan.duration_seconds if scan else None,
        )
        for repo, scan in rows
    ]
    return RepositoryList(items=items, total=len(items))


@router.get(
    "/{repo_id}",
    response_model=RepositoryListItem,
    summary="Get one repository (with its most recent scan summary).",
)
async def get_repo(repo_id: UUID, _: CurrentUser, db: DbSession) -> RepositoryListItem:
    repo = await db.get(Repository, repo_id)
    if repo is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="repo not found")
    latest = await db.scalar(
        select(ScanJob)
        .where(ScanJob.repository_id == repo_id)
        .order_by(ScanJob.created_at.desc())
        .limit(1)
    )
    return RepositoryListItem(
        id=repo.id,
        org_id=repo.org_id,
        source_connection_id=repo.source_connection_id,
        full_name=repo.full_name,
        clone_url=repo.clone_url,
        default_branch=repo.default_branch,
        is_archived=repo.is_archived,
        last_scanned_at=repo.last_scanned_at,
        last_scan_id=latest.id if latest else None,
        last_scan_status=latest.status if latest else None,
        last_scan_finished_at=latest.finished_at if latest else None,
        last_scan_duration_seconds=latest.duration_seconds if latest else None,
    )


@router.post(
    "/{repo_id}/refresh",
    status_code=status.HTTP_501_NOT_IMPLEMENTED,
    summary="Refresh repo metadata from provider",
)
async def refresh_repo(repo_id: UUID, _: CurrentUser) -> dict[str, str]:
    return {"status": "not_implemented", "repo_id": str(repo_id)}
