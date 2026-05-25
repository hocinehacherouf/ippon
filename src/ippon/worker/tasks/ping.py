"""Smoke-test tasks — one per queue, plus the beat tick.

Useful for verifying that the API can enqueue, the broker is reachable, and
the right worker container is picking up the right queue.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from celery import shared_task

LOG = logging.getLogger("ippon.worker.ping")


@shared_task(name="ippon.worker.tasks.ping.general_ping")
def general_ping(payload: str = "hello") -> dict[str, Any]:
    LOG.info("general_ping payload=%r pid=%d", payload, os.getpid())
    return {"queue": "general", "payload": payload, "pid": os.getpid()}


@shared_task(name="ippon.worker.tasks.ping.scan_ping")
def scan_ping(payload: str = "hello") -> dict[str, Any]:
    LOG.info("scan_ping payload=%r pid=%d", payload, os.getpid())
    return {"queue": "scan", "payload": payload, "pid": os.getpid()}
