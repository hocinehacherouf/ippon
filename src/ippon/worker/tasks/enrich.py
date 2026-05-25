"""Finding-enrichment tasks (OSV/EPSS/etc.) — stubs.

Out of scope for the scaffold; the API enqueues this task on scan completion
so the downstream wiring is exercised end-to-end without doing any work yet.
"""

from __future__ import annotations

import logging

from celery import shared_task

LOG = logging.getLogger("ippon.worker.enrich")


@shared_task(name="ippon.worker.tasks.enrich.enrich_findings")
def enrich_findings(scan_id: str) -> dict[str, str]:
    LOG.info("[stub] enrich_findings scan_id=%s — real enrichment lands post-scaffold", scan_id)
    return {"status": "not_implemented", "scan_id": scan_id}
