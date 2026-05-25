"""Celery task modules.

Importing this package eagerly imports every submodule so each
``@shared_task`` registers itself with the live :data:`celery_app`.
"""

from ippon.worker.tasks import enrich, notify, ping, scan  # noqa: F401
