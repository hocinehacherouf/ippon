"""Sanity tests for the Celery app + task registry."""

from __future__ import annotations

from ippon.worker.celery_app import celery_app


def test_app_has_expected_queues() -> None:
    queue_names = {q.name for q in (celery_app.conf.task_queues or [])}
    assert queue_names == {"general", "scan"}


def test_default_queue_is_general() -> None:
    assert celery_app.conf.task_default_queue == "general"


def test_scan_tasks_route_to_scan_queue() -> None:
    routes = celery_app.conf.task_routes or {}
    assert routes.get("ippon.worker.tasks.scan.*") == {"queue": "scan"}
    assert routes.get("ippon.worker.tasks.ping.scan_ping") == {"queue": "scan"}


def test_all_tasks_registered() -> None:
    expected = {
        "ippon.worker.tasks.ping.general_ping",
        "ippon.worker.tasks.ping.scan_ping",
        "ippon.worker.tasks.scan.run_scan",
        "ippon.worker.tasks.enrich.enrich_findings",
        "ippon.worker.tasks.notify.send_scan_completed",
    }
    assert expected.issubset(set(celery_app.tasks.keys()))


def test_beat_schedule_has_tick() -> None:
    assert "tick-every-hour" in (celery_app.conf.beat_schedule or {})


def test_ping_tasks_are_callable_locally() -> None:
    from ippon.worker.tasks.ping import general_ping, scan_ping

    # ``.apply()`` runs the task synchronously in-process without a broker.
    g = general_ping.apply(kwargs={"payload": "hi"}).get()
    s = scan_ping.apply(kwargs={"payload": "hi"}).get()
    assert g["queue"] == "general"
    assert s["queue"] == "scan"
    assert g["payload"] == "hi"
