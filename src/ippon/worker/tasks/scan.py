"""Scan orchestration task.

Steps:

1. Load the ``scan_jobs`` row.
2. Update status → ``running``.
3. Build a ``ScanJobSpec`` via the pipeline helper.
4. Call ``runner.submit(spec)`` — blocks until the chain finishes.

On exception, mark the scan ``failed`` if the reporter callback didn't beat
us to it (the callback handler is idempotent).
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from uuid import UUID

from celery import shared_task

from ippon.config import Settings, get_settings
from ippon.db import make_sync_engine, make_sync_session_factory, sync_session_scope
from ippon.models import Repository, ScanJob, ScanJobStatus
from ippon.scanner.pipeline import build_scan_job_spec
from ippon.scanner.runner.base import JobRunner, ScanJobSpec
from ippon.scanner.runner.docker import DockerJobRunner

LOG = logging.getLogger("ippon.worker.scan")


def _make_runner(backend: str, settings: Settings) -> JobRunner:
    if backend == "docker":
        return DockerJobRunner()
    if backend == "inline":
        from ippon.scanner.runner.inline import InlineJobRunner

        return InlineJobRunner()
    if backend == "k8s":
        from ippon.scanner.runner.k8s import K8sJobRunner

        return K8sJobRunner(
            namespace=settings.k8s_namespace,
            service_account=settings.k8s_service_account,
            grype_db_pvc=settings.k8s_grype_db_pvc,
            kubeconfig=settings.k8s_kubeconfig,
            context=settings.k8s_context,
        )
    raise ValueError(f"unknown JobRunner backend: {backend!r}")


@shared_task(name="ippon.worker.tasks.scan.run_scan", bind=True)
def run_scan(self, scan_id: str) -> dict[str, str]:  # type: ignore[no-untyped-def]
    settings = get_settings()
    engine = make_sync_engine(settings)
    factory = make_sync_session_factory(engine)

    spec: ScanJobSpec | None = None
    backend_name: str | None = None
    try:
        with sync_session_scope(factory) as session:
            scan = session.get(ScanJob, UUID(scan_id))
            if scan is None:
                LOG.error("run_scan: scan %s not found", scan_id)
                return {"status": "not_found", "scan_id": scan_id}
            repo = session.get(Repository, scan.repository_id)
            if repo is None:
                LOG.error("run_scan: repo %s not found", scan.repository_id)
                scan.status = ScanJobStatus.failed
                scan.error_message = "repository row missing"
                scan.finished_at = datetime.now(UTC)
                return {"status": "failed", "scan_id": scan_id}

            scan.status = ScanJobStatus.running
            scan.started_at = datetime.now(UTC)
            backend_name = scan.backend.value
            spec = build_scan_job_spec(settings=settings, scan=scan, repo=repo)

        assert spec is not None and backend_name is not None
        runner = _make_runner(backend_name, settings)
        handle = asyncio.run(runner.submit(spec))
        return {"scan_id": scan_id, "handle": handle.handle, "backend": handle.backend}

    except Exception as exc:
        LOG.exception("run_scan failed scan_id=%s", scan_id)
        # Backstop: if the reporter callback didn't already record a terminal
        # state, mark the scan failed now so it doesn't get stuck running.
        with sync_session_scope(factory) as session:
            scan = session.get(ScanJob, UUID(scan_id))
            if scan and scan.status not in (
                ScanJobStatus.succeeded,
                ScanJobStatus.failed,
                ScanJobStatus.cancelled,
            ):
                scan.status = ScanJobStatus.failed
                scan.error_message = f"runner error: {type(exc).__name__}: {exc}"[:1024]
                scan.finished_at = datetime.now(UTC)
        raise
    finally:
        engine.dispose()
