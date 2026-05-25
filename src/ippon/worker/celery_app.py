"""Celery application instance.

Two queues:

- ``general`` — default; everything that isn't a scan job.
- ``scan`` — long-running scan-orchestration tasks (M6 onward). The
  ``worker-scan`` compose service binds only to this queue and is the only
  worker that mounts the shared Grype DB volume.

Tasks are declared with :func:`celery.shared_task` in
``ippon.worker.tasks.*`` modules; they are eagerly imported by
``ippon.worker.tasks.__init__`` so the registry is fully populated as soon as
the app is constructed.

The instance reads broker/result URLs from :class:`ippon.config.Settings` at
import time. The same module is imported by the FastAPI app (which uses it to
enqueue) and by the worker container (which uses it to consume); both call
``celery -A ippon.worker.celery_app:celery_app worker``.
"""

from __future__ import annotations

from celery import Celery
from celery.schedules import crontab
from kombu import Queue

from ippon.config import Settings, get_settings


def _make_celery_app(settings: Settings) -> Celery:
    app = Celery("ippon")
    app.conf.update(
        broker_url=settings.valkey_url,
        result_backend=settings.valkey_url,
        # Queue layout.
        task_default_queue="general",
        task_queues=(Queue("general"), Queue("scan")),
        task_routes={
            "ippon.worker.tasks.scan.*": {"queue": "scan"},
            "ippon.worker.tasks.ping.scan_ping": {"queue": "scan"},
        },
        # Serialization + reliability.
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        timezone="UTC",
        enable_utc=True,
        task_track_started=True,
        task_acks_late=True,
        worker_prefetch_multiplier=1,
        broker_connection_retry_on_startup=True,
        result_expires=3600,
        # Beat schedule — stub; placeholder so the beat container has work.
        # Real schedules (grype DB refresh trigger, repo polling, etc.) land
        # post-scaffold. The ``tick`` task is intentionally a no-op.
        beat_schedule={
            "tick-every-hour": {
                "task": "ippon.worker.tasks.ping.general_ping",
                "schedule": crontab(minute=0),
                "args": ("beat-tick",),
            },
        },
    )
    # Eagerly import the tasks package so ``@shared_task`` definitions are
    # bound to this app before any worker / sender uses it.
    import ippon.worker.tasks  # noqa: F401

    return app


celery_app = _make_celery_app(get_settings())
