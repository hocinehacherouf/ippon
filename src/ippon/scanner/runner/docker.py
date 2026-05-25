"""DockerJobRunner — local-dev backend.

Drives the scan chain by running four containers in sequence on the local
Docker daemon:

    1. ``alpine/git``      — shallow clone the repo into ``/workspace``
    2. ``anchore/syft``    — emit ``/artifacts/sbom.json``
    3. ``anchore/grype``   — emit ``/artifacts/findings.json``
    4. ``ippon/reporter``  — upload, ingest, callback

Each step writes into per-scan Docker volumes so containers don't share host
state. On any non-zero exit, the chain short-circuits to the reporter with
``IPPON_FAILED=1`` so the API always gets a callback.

``submit`` blocks until the whole chain finishes — there is no separate "job
controller" on the Docker side, so the worker slot that called us is the
job controller for the duration.

Containers are NOT auto-removed (so ``docker ps -a --filter
label=ippon.scan-id`` shows the chain). Per-scan volumes ARE removed in the
``finally`` block to avoid disk bloat.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import aiodocker

from ippon.scanner.runner.base import JobHandle, JobStatus, ScanJobSpec

LOG = logging.getLogger("ippon.scanner.docker")

_LABEL_APP = "app"
_LABEL_SCAN = "ippon.scan-id"
_LABEL_ORG = "ippon.org-id"
_LABEL_REPO = "ippon.repo-id"
_LABEL_STEP = "ippon.step"

_CLONE_ENTRYPOINT_CMD = (
    "set -e; "
    'if [ -n "$IPPON_REF" ] && [ "$IPPON_REF" != "HEAD" ]; then '
    '  git clone --depth=1 --branch "$IPPON_REF" "$IPPON_REPO_URL" /workspace; '
    "else "
    '  git clone --depth=1 "$IPPON_REPO_URL" /workspace; '
    "fi; "
    "git -C /workspace rev-parse HEAD > /artifacts/commit-sha.txt; "
    "echo cloned ${IPPON_REPO_URL} ref=${IPPON_REF:-default} sha=$(cat /artifacts/commit-sha.txt)"
)


@dataclass
class _StepResult:
    name: str
    exit_code: int
    duration_seconds: float
    logs_tail: str


class DockerJobRunner:
    """Runs a scan chain on the local Docker daemon via ``aiodocker``."""

    def __init__(self, docker_url: str | None = None) -> None:
        # ``aiodocker.Docker()`` reads ``DOCKER_HOST`` from the env; explicit
        # URL is for tests against a fake daemon.
        self._docker_url = docker_url

    async def submit(self, spec: ScanJobSpec) -> JobHandle:
        labels = self._base_labels(spec)
        scan_id_short = str(spec.scan_id)[:8]
        ws_volume = f"ippon-scan-{spec.scan_id}-workspace"
        ar_volume = f"ippon-scan-{spec.scan_id}-artifacts"
        scan_started_at = datetime.now(UTC)

        async with aiodocker.Docker(url=self._docker_url) as docker:
            await self._ensure_image(docker, spec.clone_image)
            await self._ensure_image(docker, spec.syft_image)
            await self._ensure_image(docker, spec.grype_image)
            await self._ensure_image(docker, spec.reporter_image)

            await self._create_volume(docker, ws_volume, labels)
            await self._create_volume(docker, ar_volume, labels)

            failed_step: str | None = None
            failed_reason: str | None = None
            try:
                # 1. Clone.
                step = await self._run_step(
                    docker,
                    name="clone",
                    image=spec.clone_image,
                    cmd=["sh", "-c", _CLONE_ENTRYPOINT_CMD],
                    entrypoint=[],  # override the alpine/git default entrypoint
                    env={"IPPON_REPO_URL": spec.repo_url, "IPPON_REF": spec.ref},
                    volumes={ws_volume: "/workspace", ar_volume: "/artifacts"},
                    network_mode="bridge",
                    labels={**labels, _LABEL_STEP: "clone"},
                    name_suffix=f"clone-{scan_id_short}",
                    mem_limit=spec.mem_limit,
                    cpu_count=spec.cpu_count,
                    deadline_seconds=spec.active_deadline_seconds,
                )
                if step.exit_code != 0:
                    failed_step, failed_reason = "clone", step.logs_tail

                # 2. Syft.
                if failed_step is None:
                    step = await self._run_step(
                        docker,
                        name="syft",
                        image=spec.syft_image,
                        cmd=[
                            "dir:/workspace",
                            "-o",
                            "cyclonedx-json=/artifacts/sbom.json",
                            "--quiet",
                        ],
                        env={},
                        volumes={ws_volume: "/workspace", ar_volume: "/artifacts"},
                        network_mode="none",
                        labels={**labels, _LABEL_STEP: "syft"},
                        name_suffix=f"syft-{scan_id_short}",
                        mem_limit=spec.mem_limit,
                        cpu_count=spec.cpu_count,
                        deadline_seconds=spec.active_deadline_seconds,
                    )
                    if step.exit_code != 0:
                        failed_step, failed_reason = "syft", step.logs_tail

                # 3. Grype.
                if failed_step is None:
                    step = await self._run_step(
                        docker,
                        name="grype",
                        image=spec.grype_image,
                        cmd=[
                            "sbom:/artifacts/sbom.json",
                            "-o",
                            "json",
                            "--file",
                            "/artifacts/findings.json",
                            "--quiet",
                        ],
                        env={
                            "GRYPE_DB_CACHE_DIR": "/grype-db",
                            "GRYPE_DB_AUTO_UPDATE": "false",
                            "GRYPE_DB_VALIDATE_AGE": "false",
                        },
                        volumes={
                            ar_volume: "/artifacts",
                            spec.grype_db_volume: ("/grype-db", "ro"),
                        },
                        network_mode="none",
                        labels={**labels, _LABEL_STEP: "grype"},
                        name_suffix=f"grype-{scan_id_short}",
                        mem_limit=spec.mem_limit,
                        cpu_count=spec.cpu_count,
                        deadline_seconds=spec.active_deadline_seconds,
                    )
                    if step.exit_code != 0:
                        failed_step, failed_reason = "grype", step.logs_tail

                # 4. Reporter — always runs, with FAILED env on short-circuit.
                reporter_env: dict[str, str] = {
                    **spec.reporter_env,
                    "IPPON_SCAN_ID": str(spec.scan_id),
                    "IPPON_ORG_ID": str(spec.org_id),
                    "IPPON_REPO_ID": str(spec.repo_id),
                    "IPPON_CALLBACK_URL": spec.callback_url,
                    "IPPON_CALLBACK_SECRET": spec.callback_secret,
                    "IPPON_SCAN_STARTED_AT": scan_started_at.isoformat(),
                }
                if failed_step is not None:
                    reporter_env["IPPON_FAILED"] = "1"
                    reporter_env["IPPON_FAILED_STEP"] = failed_step
                    reporter_env["IPPON_FAILED_REASON"] = (failed_reason or "")[:1024]

                # The consolidated backend image has no ENTRYPOINT/CMD —
                # supply the full invocation here.
                step = await self._run_step(
                    docker,
                    name="reporter",
                    image=spec.reporter_image,
                    cmd=["python", "-m", "ippon.reporter"],
                    env=reporter_env,
                    volumes={ar_volume: "/artifacts"},
                    network_mode=spec.network,
                    labels={**labels, _LABEL_STEP: "reporter"},
                    name_suffix=f"reporter-{scan_id_short}",
                    mem_limit=spec.mem_limit,
                    cpu_count=spec.cpu_count,
                    deadline_seconds=spec.active_deadline_seconds,
                )
                if step.exit_code != 0 and failed_step is None:
                    failed_step, failed_reason = "reporter", step.logs_tail
            finally:
                await self._delete_volume(docker, ws_volume)
                await self._delete_volume(docker, ar_volume)

        return JobHandle(scan_id=spec.scan_id, backend="docker", handle=str(spec.scan_id))

    async def status(self, handle: JobHandle) -> JobStatus:
        """Inspect the latest step container's state."""
        async with aiodocker.Docker(url=self._docker_url) as docker:
            containers = await docker.containers.list(
                all=True, filters={"label": [f"{_LABEL_SCAN}={handle.scan_id}"]}
            )
            if not containers:
                return JobStatus.not_found
            # Sort by creation time, latest last.
            latest = containers[-1]
            state = (await latest.show()).get("State", {})
            running = bool(state.get("Running"))
            exit_code = state.get("ExitCode", 0)
            if running:
                return JobStatus.running
            if (
                exit_code == 0
                and (await latest.show())["Config"]["Labels"].get(_LABEL_STEP) == "reporter"
            ):
                return JobStatus.succeeded
            if exit_code != 0:
                return JobStatus.failed
            return JobStatus.pending

    async def cleanup(self, handle: JobHandle) -> None:
        """Remove all containers for a scan. Volumes are removed by ``submit``'s
        finally block, so this just sweeps the containers."""
        async with aiodocker.Docker(url=self._docker_url) as docker:
            containers = await docker.containers.list(
                all=True, filters={"label": [f"{_LABEL_SCAN}={handle.scan_id}"]}
            )
            for c in containers:
                try:
                    await c.delete(force=True)
                except aiodocker.exceptions.DockerError:
                    LOG.exception("failed to delete container %s", c.id)

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _base_labels(spec: ScanJobSpec) -> dict[str, str]:
        return {
            _LABEL_APP: "ippon",
            _LABEL_SCAN: str(spec.scan_id),
            _LABEL_ORG: str(spec.org_id),
            _LABEL_REPO: str(spec.repo_id),
        }

    async def _ensure_image(self, docker: aiodocker.Docker, image: str) -> None:
        try:
            await docker.images.inspect(image)
            return
        except aiodocker.exceptions.DockerError as exc:
            if exc.status != 404:
                raise
        LOG.info("pulling image %s", image)
        await docker.images.pull(image)

    async def _create_volume(
        self, docker: aiodocker.Docker, name: str, labels: dict[str, str]
    ) -> None:
        await docker.volumes.create({"Name": name, "Labels": labels, "Driver": "local"})

    async def _delete_volume(self, docker: aiodocker.Docker, name: str) -> None:
        try:
            vol = await docker.volumes.get(name)
            await vol.delete()
        except aiodocker.exceptions.DockerError as exc:
            if exc.status != 404:
                LOG.warning("could not delete volume %s: %s", name, exc)

    async def _run_step(
        self,
        docker: aiodocker.Docker,
        *,
        name: str,
        image: str,
        cmd: list[str],
        env: dict[str, str],
        volumes: dict[str, str | tuple[str, str]],
        network_mode: str,
        labels: dict[str, str],
        name_suffix: str,
        mem_limit: str,
        cpu_count: float,
        deadline_seconds: int,
        entrypoint: list[str] | None = None,
    ) -> _StepResult:
        # aiodocker config keys mirror the Docker Engine REST API.
        host_config: dict[str, Any] = {
            "Binds": [
                f"{vol}:{tgt}" if isinstance(tgt, str) else f"{vol}:{tgt[0]}:{tgt[1]}"
                for vol, tgt in volumes.items()
            ],
            "Memory": _parse_mem_limit(mem_limit),
            "NanoCpus": int(cpu_count * 1_000_000_000),
            "NetworkMode": network_mode,
            "AutoRemove": False,
        }
        config: dict[str, Any] = {
            "Image": image,
            "Cmd": cmd,
            "Env": [f"{k}={v}" for k, v in env.items()],
            "Labels": labels,
            "HostConfig": host_config,
            "AttachStdout": True,
            "AttachStderr": True,
            "StopTimeout": deadline_seconds,
        }
        if entrypoint is not None:
            # An empty list disables the image entrypoint, matching docker CLI.
            config["Entrypoint"] = entrypoint if entrypoint else [""]
        container_name = f"ippon-{name_suffix}"
        LOG.info("step=%s image=%s container=%s", name, image, container_name)
        start = datetime.now(UTC)
        container = await docker.containers.create_or_replace(name=container_name, config=config)
        await container.start()
        exit_info = await container.wait(timeout=deadline_seconds)
        duration = (datetime.now(UTC) - start).total_seconds()
        exit_code = int(exit_info.get("StatusCode", -1))
        logs = "".join(await container.log(stdout=True, stderr=True, tail=200))
        LOG.info("step=%s exit=%d duration=%.2fs", name, exit_code, duration)
        if exit_code != 0:
            LOG.warning("step=%s logs (tail):\n%s", name, logs)
        return _StepResult(
            name=name, exit_code=exit_code, duration_seconds=duration, logs_tail=logs
        )


_MEM_SUFFIXES = {"b": 1, "k": 1024, "m": 1024**2, "g": 1024**3}


def _parse_mem_limit(value: str) -> int:
    s = value.strip().lower()
    if not s:
        return 0
    suffix = s[-1]
    if suffix in _MEM_SUFFIXES:
        return int(float(s[:-1]) * _MEM_SUFFIXES[suffix])
    return int(s)
