"""``JobRunner`` Protocol + backend-agnostic data classes.

The three concrete backends — ``DockerJobRunner`` (dev), ``K8sJobRunner``
(prod, M7), ``InlineJobRunner`` (tests) — all implement this protocol so the
worker only knows one shape.

Extending to a Renovate job (or any other tool that follows the same
clone-then-tool-then-report pattern) means writing a new
``RenovateJobRunner`` against this same protocol, or extending
``K8sJobRunner`` with a new ``JobSpec`` variant. Don't build it now — leave
the door open.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


class JobStatus(enum.StrEnum):
    """Lifecycle states reported by the runner.

    These are the *backend's* view of the job — distinct from the
    ``scan_jobs.status`` column on the API side, which reflects the
    full business state (callback received, downstream tasks enqueued, etc.).
    """

    not_found = "not_found"
    pending = "pending"
    running = "running"
    succeeded = "succeeded"
    failed = "failed"


@dataclass(frozen=True, slots=True)
class JobHandle:
    """Opaque identifier returned by ``submit``.

    The ``backend`` discriminator lets callers fan back out to the right
    runner for ``status`` / ``cleanup`` even when handles for multiple
    backends coexist (e.g. during a migration).
    """

    scan_id: uuid.UUID
    backend: str  # "docker" | "k8s" | "inline"
    handle: str  # docker: scan_id prefix; k8s: Job name; inline: synthetic


@dataclass(frozen=True, slots=True)
class ScanJobSpec:
    """Backend-agnostic specification of one scan job.

    Built by ``ippon.scanner.pipeline.build_scan_job_spec`` from a
    ``scan_jobs`` row + global settings; passed to whichever ``JobRunner``
    is wired up. Everything the runner needs to start the chain is in here
    — no DB reads from inside the runner.
    """

    scan_id: uuid.UUID
    org_id: uuid.UUID
    repo_id: uuid.UUID

    # Source repository.
    repo_url: str
    ref: str  # branch, tag, or commit sha

    # Per-step images. Versions are baked into the tag.
    clone_image: str
    syft_image: str
    grype_image: str
    reporter_image: str

    # Where the Grype DB lives (a Docker volume name for the Docker backend,
    # a PVC claim name for the K8s backend).
    grype_db_volume: str

    # Compose / k8s network the reporter joins to reach API/CH/RustFS.
    network: str

    # Reporter ↔ API authentication.
    callback_url: str
    callback_secret: str

    # Env vars the reporter needs to talk to RustFS + ClickHouse.
    reporter_env: dict[str, str] = field(default_factory=dict)

    # Resource caps (per container). ``mem_limit`` is a Kubernetes-style
    # quantity (e.g. ``2Gi``) — valid as-is in the K8s Job manifest, and
    # parsed to bytes by the Docker backend's ``_parse_mem_limit``.
    mem_limit: str = "2Gi"
    cpu_count: float = 1.0

    # Hard ceiling on total wall-clock for the chain.
    active_deadline_seconds: int = 900


@runtime_checkable
class JobRunner(Protocol):
    """Three-method interface every backend implements.

    Implementations must be cheap to construct — typically a thin wrapper
    around a long-lived client (an aiodocker ``Docker``, a
    ``kubernetes_asyncio.client.ApiClient``). Construct once per process.
    """

    async def submit(self, spec: ScanJobSpec) -> JobHandle:
        """Create / start the job and return a handle.

        The K8s backend returns once the Job is admitted (containers not yet
        running). The Docker backend, lacking a Job controller, blocks until
        the whole chain finishes — see backend docstring for details. Either
        way, completion is canonically signalled via the reporter's HMAC
        callback to the API, not by this method returning.
        """

    async def status(self, handle: JobHandle) -> JobStatus:
        """Backend-side view of the job. Used by the orphan reaper, not by the
        scan happy-path."""

    async def cleanup(self, handle: JobHandle) -> None:
        """Best-effort teardown of containers / volumes / Job objects.
        Idempotent — safe to call after a job has already self-cleaned."""
