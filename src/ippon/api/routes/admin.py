"""Admin / smoke-test routes.

For now this exposes a ``ping`` round-trip against Celery so we can verify
the API → broker → worker → result-backend path is healthy from the API side
without running a full scan.
"""

from __future__ import annotations

import asyncio
from typing import Annotated, Literal

from celery.result import AsyncResult
from fastapi import APIRouter, Path, status

from ippon.api.deps import CurrentUser
from ippon.worker.celery_app import celery_app

router = APIRouter(prefix="/admin", tags=["admin"])

Queue = Literal["general", "scan"]

_TASK_BY_QUEUE: dict[Queue, str] = {
    "general": "ippon.worker.tasks.ping.general_ping",
    "scan": "ippon.worker.tasks.ping.scan_ping",
}


@router.post(
    "/ping/{queue}",
    summary="Enqueue a ping task on the given queue",
    status_code=status.HTTP_202_ACCEPTED,
)
async def enqueue_ping(
    queue: Annotated[Queue, Path(description="Target queue name")],
    _: CurrentUser,
    payload: str = "hi",
) -> dict[str, str]:
    task_name = _TASK_BY_QUEUE[queue]
    # send_task does a synchronous broker publish; offload to a thread so we
    # don't block the event loop on a slow broker connection.
    result = await asyncio.to_thread(
        celery_app.send_task, task_name, kwargs={"payload": payload}, queue=queue
    )
    return {"task_id": result.id, "queue": queue, "task": task_name}


@router.get(
    "/ping/{task_id}",
    summary="Fetch the result of a previously-enqueued ping",
)
async def get_ping_result(
    task_id: Annotated[
        str, Path(description="Celery task id returned by POST /admin/ping/{queue}")
    ],
    _: CurrentUser,
) -> dict[str, object]:
    result = AsyncResult(task_id, app=celery_app)
    state = result.state
    body: dict[str, object] = {"task_id": task_id, "state": state}
    if result.ready():
        if result.successful():
            body["result"] = result.result
        else:
            body["error"] = str(result.result)
    elif state == "PENDING":
        # Celery returns ``PENDING`` for both "haven't seen this id" and
        # "queued but not started"; we can't distinguish from the client.
        body["note"] = "task is pending or unknown"
    return body
