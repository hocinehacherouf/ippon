"""Machine-to-machine routes.

These do **not** use the bearer-token auth — they're authenticated by HMAC
signatures against per-call secrets, and they are not part of the public API
surface (excluded from OpenAPI by tag).

The only endpoint here is the reporter callback; future M6+ work
(orphan-job reaper webhook, etc.) lands under the same prefix.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, status

from ippon.api.deps import DbSession
from ippon.models import ScanJob, ScanJobStatus
from ippon.schemas.scan import CallbackPayload
from ippon.security import verify_hmac_sha256
from ippon.worker.celery_app import celery_app

router = APIRouter(prefix="/internal", tags=["internal"])

SIGNATURE_HEADER = "X-Ippon-Signature-256"


@router.post(
    "/scans/{scan_id}/callback",
    summary="Receive the reporter's signed scan-completion callback",
)
async def scan_callback(scan_id: UUID, request: Request, db: DbSession) -> dict[str, str]:
    body = await request.body()
    signature = request.headers.get(SIGNATURE_HEADER)
    if not signature:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"missing {SIGNATURE_HEADER}",
        )

    scan = await db.get(ScanJob, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")

    if not verify_hmac_sha256(signature, body, scan.callback_secret.encode("utf-8")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"invalid {SIGNATURE_HEADER}",
        )

    payload = CallbackPayload.model_validate_json(body)
    if payload.scan_id != scan_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="payload scan_id mismatch",
        )

    # Idempotency: once we've recorded a terminal state, ignore re-deliveries.
    if scan.status in (
        ScanJobStatus.succeeded,
        ScanJobStatus.failed,
        ScanJobStatus.cancelled,
    ):
        return {"status": "duplicate", "current": scan.status.value}

    scan.status = ScanJobStatus.succeeded if payload.status == "succeeded" else ScanJobStatus.failed
    scan.finished_at = payload.finished_at
    scan.resolved_commit_sha = payload.commit_sha
    scan.sbom_object_key = payload.object_key
    scan.sbom_sha256 = payload.sbom_sha256
    scan.syft_version = payload.syft_version
    scan.grype_version = payload.grype_version
    scan.grype_db_version = payload.grype_db_version
    scan.error_message = payload.error_message
    if scan.started_at and scan.finished_at:
        scan.duration_seconds = (scan.finished_at - scan.started_at).total_seconds()

    if scan.status == ScanJobStatus.succeeded:
        # Stubs for now; will do real work post-scaffold.
        celery_app.send_task(
            "ippon.worker.tasks.enrich.enrich_findings",
            kwargs={"scan_id": str(scan_id)},
            queue="general",
        )
        celery_app.send_task(
            "ippon.worker.tasks.notify.send_scan_completed",
            kwargs={"scan_id": str(scan_id)},
            queue="general",
        )

    return {"status": "accepted", "scan_status": scan.status.value}
