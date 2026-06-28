"""InlineJobRunner — subprocess fallback for fast unit tests.

Runs ``git`` + ``syft`` + ``grype`` directly on the host (no Docker), then
invokes the reporter as an in-process function call rather than launching a
container. Skips ingest+callback when the binaries aren't installed; the test
harness should mark itself as skipped in that case.

Not intended for any real workload — production uses ``K8sJobRunner``, dev
uses ``DockerJobRunner``. This runner exists so we can exercise the JobRunner
protocol without spinning up Docker in CI's unit-test job.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

from ippon.scanner.runner.base import JobHandle, JobStatus, ScanJobSpec

LOG = logging.getLogger("ippon.scanner.inline")


class MissingToolError(RuntimeError):
    """Raised at construction time when ``syft`` or ``grype`` isn't on PATH."""


class InlineJobRunner:
    def __init__(self) -> None:
        missing = [t for t in ("git", "syft", "grype") if shutil.which(t) is None]
        if missing:
            raise MissingToolError(
                f"InlineJobRunner needs {missing!r} on PATH; install or use DockerJobRunner"
            )

    async def submit(self, spec: ScanJobSpec) -> JobHandle:
        # All work happens inside a tempdir; on success we tear it down.
        loop = asyncio.get_event_loop()
        with tempfile.TemporaryDirectory(prefix="ippon-inline-") as tmp:
            workspace = Path(tmp) / "workspace"
            artifacts = Path(tmp) / "artifacts"
            artifacts.mkdir(parents=True, exist_ok=True)

            await loop.run_in_executor(None, self._clone, spec, workspace, artifacts)
            await loop.run_in_executor(None, self._syft, workspace, artifacts)
            await loop.run_in_executor(None, self._grype, artifacts)

        return JobHandle(scan_id=spec.scan_id, backend="inline", handle=str(spec.scan_id))

    async def status(self, handle: JobHandle) -> JobStatus:
        return JobStatus.succeeded  # inline runner is synchronous; if submit returned, we're done

    async def cleanup(self, handle: JobHandle) -> None:
        # Tempdir cleanup is automatic via the ``with`` block above.
        return None

    @staticmethod
    def _clone_cmd(spec: ScanJobSpec, workspace: Path) -> list[str]:
        depth = spec.secret_history_depth if spec.secret_scan_enabled else 1
        cmd = ["git", "clone", f"--depth={depth}"]
        if spec.ref and spec.ref != "HEAD":
            cmd += ["--branch", spec.ref]
        cmd += [spec.repo_url, str(workspace)]
        return cmd

    @staticmethod
    def _clone(spec: ScanJobSpec, workspace: Path, artifacts: Path) -> None:
        LOG.info("[inline] cloning %s ref=%s", spec.repo_url, spec.ref)
        subprocess.run(
            InlineJobRunner._clone_cmd(spec, workspace),
            check=True,
            capture_output=True,
        )
        sha = subprocess.run(
            ["git", "-C", str(workspace), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        (artifacts / "commit-sha.txt").write_text(sha + "\n", encoding="utf-8")

    @staticmethod
    def _syft(workspace: Path, artifacts: Path) -> None:
        LOG.info("[inline] syft %s", workspace)
        subprocess.run(
            [
                "syft",
                f"dir:{workspace}",
                "-o",
                f"cyclonedx-json={artifacts / 'sbom.json'}",
                "--quiet",
            ],
            check=True,
            capture_output=True,
        )

    @staticmethod
    def _grype(artifacts: Path) -> None:
        LOG.info("[inline] grype")
        subprocess.run(
            [
                "grype",
                f"sbom:{artifacts / 'sbom.json'}",
                "-o",
                "json",
                "--file",
                str(artifacts / "findings.json"),
                "--quiet",
            ],
            check=True,
            capture_output=True,
        )
