"""Build a ``ScanJobSpec`` from a ``scan_jobs`` row + ambient ``Settings``.

Kept as a pure function so the worker / API / tests can all use it without
pulling in any JobRunner backend.
"""

from __future__ import annotations

from ippon.config import Settings
from ippon.models import Repository, ScanJob
from ippon.scanner.runner.base import ScanJobSpec


def build_scan_job_spec(
    *,
    settings: Settings,
    scan: ScanJob,
    repo: Repository,
) -> ScanJobSpec:
    callback_url = f"{settings.callback_base_url.rstrip('/')}/internal/scans/{scan.id}/callback"
    # Env vars handed to the reporter container.
    reporter_env: dict[str, str] = {
        "CLICKHOUSE_URL": settings.clickhouse_url,
        "S3_ENDPOINT_URL": settings.s3_endpoint_url,
        "S3_BUCKET": settings.s3_bucket,
        "AWS_ACCESS_KEY_ID": settings.rustfs_access_key,
        "AWS_SECRET_ACCESS_KEY": settings.rustfs_secret_key,
    }
    return ScanJobSpec(
        scan_id=scan.id,
        org_id=scan.org_id,
        repo_id=scan.repository_id,
        repo_url=repo.clone_url,
        ref=scan.requested_ref,
        clone_image=settings.clone_image,
        syft_image=settings.syft_image,
        grype_image=settings.grype_image,
        reporter_image=settings.reporter_image,
        grype_db_volume=settings.grype_db_volume,
        network=settings.scan_job_network,
        callback_url=callback_url,
        callback_secret=scan.callback_secret,
        reporter_env=reporter_env,
        mem_limit=settings.scan_mem_limit,
        cpu_count=settings.scan_cpu_count,
    )
