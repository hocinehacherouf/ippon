"""Scan API.

``POST /scans`` creates a ``scan_jobs`` row (registering the repo on first
sight within the caller's org) with a freshly-minted callback secret, and
enqueues ``ippon.worker.tasks.scan.run_scan`` on the ``scan`` Celery queue.
``GET /scans/{id}`` reads the row back; ``GET /scans`` lists them, newest
first. ``GET /scans/{id}/findings`` and ``GET /scans/{id}/secrets`` paginate
the matching ClickHouse rows.

Every route here is mounted under ``/orgs/{org}`` (see ``ippon.api.main``,
which also attaches the router-level ``require_org_member`` gate) and every
handler scopes its query to ``ctx.org_id``.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select

from ippon.api._bootstrap import (
    AmbiguousConnectionError,
    ConnectionNotFoundError,
    resolve_scan_target,
)
from ippon.api.authz import OrgCtx, get_scoped, require_role
from ippon.api.deps import CHDep, DbSession, SettingsDep
from ippon.clickhouse import ch_scoped
from ippon.models import JobRunnerBackend, OrgMemberRole, ScanJob, ScanJobStatus, ScanTrigger
from ippon.schemas.finding import Finding, FindingPage
from ippon.schemas.scan import ScanRequest, ScanResponse
from ippon.schemas.secret import SecretFinding, SecretFindingPage
from ippon.security import generate_callback_secret
from ippon.worker.celery_app import celery_app

router = APIRouter(prefix="/scans", tags=["scans"])

# Severity ordering for the findings table.
_SEVERITY_RANK_SQL = (
    "multiIf(severity = 'critical', 1, severity = 'high', 2, "
    "severity = 'medium', 3, severity = 'low', 4, "
    "severity = 'negligible', 5, 6)"
)


@router.post(
    "",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_role(OrgMemberRole.member))],
    summary="Enqueue a scan against a public Git repository.",
)
async def create_scan(
    body: ScanRequest,
    ctx: OrgCtx,
    db: DbSession,
    settings: SettingsDep,
) -> ScanResponse:
    try:
        _, _, repo = await resolve_scan_target(
            db,
            body.repo_url,
            org_id=ctx.org_id,
            source_connection_id=body.source_connection_id,
        )
    except ConnectionNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"source connection {exc} not found",
        ) from exc
    except AmbiguousConnectionError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"multiple connections match host {exc}; pass source_connection_id to disambiguate"
            ),
        ) from exc
    scan = ScanJob(
        org_id=repo.org_id,
        repository_id=repo.id,
        status=ScanJobStatus.queued,
        trigger=ScanTrigger.manual,
        backend=JobRunnerBackend(settings.ippon_job_runner),
        requested_ref=body.ref,
        callback_secret=generate_callback_secret(),
        queued_at=datetime.now(UTC),
    )
    db.add(scan)
    await db.flush()

    await asyncio.to_thread(
        celery_app.send_task,
        "ippon.worker.tasks.scan.run_scan",
        kwargs={"scan_id": str(scan.id)},
        queue="scan",
    )
    return ScanResponse.model_validate(scan)


@router.get(
    "/{scan_id}",
    response_model=ScanResponse,
    summary="Get scan job",
)
async def get_scan(scan_id: UUID, ctx: OrgCtx, db: DbSession) -> ScanResponse:
    scan = await get_scoped(db, ScanJob, scan_id, ctx)
    return ScanResponse.model_validate(scan)


@router.get("", response_model=list[ScanResponse], summary="List scan jobs")
async def list_scans(
    ctx: OrgCtx,
    db: DbSession,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[ScanResponse]:
    stmt = (
        select(ScanJob)
        .where(ScanJob.org_id == ctx.org_id)
        .order_by(ScanJob.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    rows = list(await db.scalars(stmt))
    return [ScanResponse.model_validate(row) for row in rows]


@router.get(
    "/{scan_id}/findings",
    response_model=FindingPage,
    summary="List findings for a scan, paginated and sorted by severity.",
)
async def list_findings(
    scan_id: UUID,
    ctx: OrgCtx,
    ch: CHDep,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    severity: Annotated[
        str | None,
        Query(
            description="Filter to a single severity (critical/high/medium/low/negligible/unknown)."
        ),
    ] = None,
) -> FindingPage:
    params: dict[str, Any] = {"scan_id": str(scan_id), "limit": limit, "offset": offset}
    where = f"{ch_scoped(ctx.org_id, params)} AND scan_id = {{scan_id:UUID}}"
    if severity:
        where += " AND severity = {severity:String}"
        params["severity"] = severity

    count_sql = f"SELECT count() FROM findings WHERE {where}"
    rows_sql = f"""
        SELECT scan_id, cve_id, purl, name, version, severity,
               fix_state, fix_versions, description, cvss_score, cvss_vector,
               matcher, scanned_at
        FROM findings
        WHERE {where}
        ORDER BY {_SEVERITY_RANK_SQL} ASC, cve_id ASC
        LIMIT {{limit:UInt32}} OFFSET {{offset:UInt32}}
    """

    total_row = await asyncio.to_thread(ch.query, count_sql, parameters=params)
    total = int(total_row.result_rows[0][0]) if total_row.result_rows else 0

    page = await asyncio.to_thread(ch.query, rows_sql, parameters=params)
    items: list[Finding] = []
    for row in page.result_rows:
        items.append(
            Finding(
                scan_id=row[0],
                cve_id=row[1],
                purl=row[2],
                name=row[3],
                version=row[4],
                severity=row[5],
                fix_state=row[6],
                fix_versions=list(row[7]) if row[7] is not None else [],
                description=row[8],
                cvss_score=row[9],
                cvss_vector=row[10],
                matcher=row[11],
                scanned_at=row[12],
            )
        )

    return FindingPage(items=items, total=total, limit=limit, offset=offset)


@router.get(
    "/{scan_id}/secrets",
    response_model=SecretFindingPage,
    summary="List secret findings for a scan, paginated.",
)
async def list_secrets(
    scan_id: UUID,
    ctx: OrgCtx,
    ch: CHDep,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    validation_status: Annotated[
        str | None,
        Query(
            description="Filter by validation status (verified/unverified/invalid/unknown/error)."
        ),
    ] = None,
) -> SecretFindingPage:
    params: dict[str, Any] = {"scan_id": str(scan_id), "limit": limit, "offset": offset}
    where = f"{ch_scoped(ctx.org_id, params)} AND scan_id = {{scan_id:UUID}}"
    if validation_status:
        where += " AND validation_status = {validation_status:String}"
        params["validation_status"] = validation_status

    count_sql = f"SELECT count() FROM secret_findings WHERE {where}"
    rows_sql = f"""
        SELECT scan_id, rule_id, description, file, start_line, end_line,
               match, fingerprint, author, email, committed_at, tags,
               verified, validation_status, is_historical, scanned_at
        FROM secret_findings
        WHERE {where}
        ORDER BY verified DESC, is_historical ASC, rule_id ASC
        LIMIT {{limit:UInt32}} OFFSET {{offset:UInt32}}
    """

    total_row = await asyncio.to_thread(ch.query, count_sql, parameters=params)
    total = int(total_row.result_rows[0][0]) if total_row.result_rows else 0

    page = await asyncio.to_thread(ch.query, rows_sql, parameters=params)
    items: list[SecretFinding] = []
    for row in page.result_rows:
        items.append(
            SecretFinding(
                scan_id=row[0],
                rule_id=row[1],
                description=row[2],
                file=row[3],
                start_line=row[4],
                end_line=row[5],
                match=row[6],
                fingerprint=row[7],
                author=row[8],
                email=row[9],
                committed_at=row[10],
                tags=list(row[11]) if row[11] is not None else [],
                verified=bool(row[12]),
                validation_status=row[13],
                is_historical=bool(row[14]),
                scanned_at=row[15],
            )
        )

    return SecretFindingPage(items=items, total=total, limit=limit, offset=offset)
