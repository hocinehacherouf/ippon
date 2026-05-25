"""Notification dispatch tasks (Slack/email/webhook) — stubs."""

from __future__ import annotations

import logging

from celery import shared_task

LOG = logging.getLogger("ippon.worker.notify")


@shared_task(name="ippon.worker.tasks.notify.send_scan_completed")
def send_scan_completed(scan_id: str) -> dict[str, str]:
    LOG.info("[stub] send_scan_completed scan_id=%s", scan_id)
    return {"status": "not_implemented", "scan_id": scan_id}
