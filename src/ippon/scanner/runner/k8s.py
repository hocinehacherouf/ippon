"""K8sJobRunner — production backend.

Renders the per-scan ``manifests/jobs/scan-job.yaml.j2`` template into a
``batch/v1.Job``, creates a sibling Secret holding the per-scan HMAC callback
secret, and submits both to the cluster. Returns once the Job is *admitted*
— the chain itself (clone → syft → grype → reporter init containers, then
the reporter main container) runs asynchronously; completion is signalled
back via the reporter's HMAC callback to the API, not by ``submit``
returning.

K8s natively sequences init containers and gates the main container on
their success, so the failure-short-circuit-to-reporter trick used by
``DockerJobRunner`` doesn't apply here. An init container failing means the
reporter never runs and no callback fires — an orphan-reaper Celery beat
task (out of scope for the scaffold) reconciles such stuck rows.

Extension: A Renovate job (or any other tool that fits the
clone-then-tool-then-report shape) lands as either a new
``RenovateJobRunner`` against the same ``JobRunner`` protocol, or as an
extension of this class with a different ``ScanJobSpec`` variant. Don't
build it now.
"""

from __future__ import annotations

import base64
import logging
from pathlib import Path
from typing import Any

import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined
from kubernetes_asyncio import client, config

from ippon.scanner.runner.base import JobHandle, JobStatus, ScanJobSpec

LOG = logging.getLogger("ippon.scanner.k8s")

TEMPLATE_DIR = Path(__file__).resolve().parents[3].parent / "manifests" / "jobs"
TEMPLATE_FILE = "scan-job.yaml.j2"


def _short_id(uuid_str: str) -> str:
    return uuid_str.split("-", 1)[0]


def _render_job_manifest(
    spec: ScanJobSpec, *, namespace: str, service_account: str, grype_db_pvc: str
) -> tuple[dict[str, Any], str, str]:
    """Render the Jinja2 template into a Job dict + return (job_dict, job_name, secret_name)."""
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        undefined=StrictUndefined,
        keep_trailing_newline=True,
        autoescape=False,
    )
    short = _short_id(str(spec.scan_id))
    job_name = f"ippon-scan-{short}"
    secret_name = f"ippon-scan-{short}-secret"
    rendered = env.get_template(TEMPLATE_FILE).render(
        scan_id=str(spec.scan_id),
        org_id=str(spec.org_id),
        repo_id=str(spec.repo_id),
        scan_id_short=short,
        job_name=job_name,
        secret_name=secret_name,
        namespace=namespace,
        service_account=service_account,
        grype_db_pvc=grype_db_pvc,
        repo_url=spec.repo_url,
        ref=spec.ref,
        clone_image=spec.clone_image,
        syft_image=spec.syft_image,
        grype_image=spec.grype_image,
        reporter_image=spec.reporter_image,
        callback_url=spec.callback_url,
        reporter_env=spec.reporter_env,
        started_at_iso="",  # populated by the runner just before submit
        active_deadline_seconds=spec.active_deadline_seconds,
        mem_limit=spec.mem_limit,
        cpu_limit=str(spec.cpu_count),
    )
    parsed = yaml.safe_load(rendered)
    if not isinstance(parsed, dict):
        raise ValueError("rendered manifest is not a YAML mapping")
    return parsed, job_name, secret_name


def _build_secret_manifest(
    *, name: str, namespace: str, callback_secret: str, owner_uid: str | None = None
) -> dict[str, Any]:
    """Build a Secret holding the per-scan callback secret.

    ``owner_uid`` (the parent Job's UID) is set after the Job is created so
    deleting the Job cascades the Secret away.
    """
    manifest: dict[str, Any] = {
        "apiVersion": "v1",
        "kind": "Secret",
        "type": "Opaque",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {"app": "ippon"},
        },
        "data": {
            "callback_secret": base64.b64encode(callback_secret.encode("utf-8")).decode("ascii"),
        },
    }
    if owner_uid:
        manifest["metadata"]["ownerReferences"] = [
            {
                "apiVersion": "batch/v1",
                "kind": "Job",
                "name": name.removesuffix("-secret"),
                "uid": owner_uid,
                "controller": True,
                "blockOwnerDeletion": True,
            }
        ]
    return manifest


class K8sJobRunner:
    """Submits scan jobs as ``batch/v1.Job`` resources via ``kubernetes-asyncio``."""

    def __init__(
        self,
        *,
        namespace: str,
        service_account: str,
        grype_db_pvc: str,
        kubeconfig: str | None = None,
        context: str | None = None,
    ) -> None:
        self.namespace = namespace
        self.service_account = service_account
        self.grype_db_pvc = grype_db_pvc
        self._kubeconfig = kubeconfig
        self._context = context

    async def _load_config(self) -> None:
        """Load kube config — in-cluster when available, else kubeconfig file."""
        try:
            config.load_incluster_config()
            LOG.debug("loaded in-cluster kube config")
            return
        except config.ConfigException:
            pass
        await config.load_kube_config(config_file=self._kubeconfig, context=self._context)
        LOG.debug("loaded kube config (file=%s, context=%s)", self._kubeconfig, self._context)

    async def submit(self, spec: ScanJobSpec) -> JobHandle:
        await self._load_config()
        job_manifest, job_name, secret_name = _render_job_manifest(
            spec,
            namespace=self.namespace,
            service_account=self.service_account,
            grype_db_pvc=self.grype_db_pvc,
        )

        async with client.ApiClient() as api_client:
            core_v1 = client.CoreV1Api(api_client)
            batch_v1 = client.BatchV1Api(api_client)

            # Create the Job first so its UID can own the Secret.
            LOG.info("creating Job %s in %s", job_name, self.namespace)
            # The kubernetes-asyncio stubs want a typed V1Job; the runtime
            # accepts a dict (it deserialises internally). Same for Secret.
            created_job = await batch_v1.create_namespaced_job(
                namespace=self.namespace,
                body=job_manifest,  # type: ignore[arg-type]
            )
            job_uid = created_job.metadata.uid

            secret_manifest = _build_secret_manifest(
                name=secret_name,
                namespace=self.namespace,
                callback_secret=spec.callback_secret,
                owner_uid=job_uid,
            )
            try:
                await core_v1.create_namespaced_secret(
                    namespace=self.namespace,
                    body=secret_manifest,  # type: ignore[arg-type]
                )
            except client.ApiException as exc:
                # If the Secret can't be created, the reporter will fail to
                # start. Best-effort cleanup of the Job we just created.
                LOG.exception("secret create failed; deleting Job %s", job_name)
                await batch_v1.delete_namespaced_job(
                    name=job_name, namespace=self.namespace, propagation_policy="Background"
                )
                raise RuntimeError(f"failed to create per-job Secret: {exc}") from exc

        return JobHandle(scan_id=spec.scan_id, backend="k8s", handle=job_name)

    async def status(self, handle: JobHandle) -> JobStatus:
        await self._load_config()
        async with client.ApiClient() as api_client:
            batch_v1 = client.BatchV1Api(api_client)
            try:
                job = await batch_v1.read_namespaced_job(
                    name=handle.handle, namespace=self.namespace
                )
            except client.ApiException as exc:
                if exc.status == 404:
                    return JobStatus.not_found
                raise
        status = job.status
        if status is None:
            return JobStatus.pending
        if getattr(status, "succeeded", None):
            return JobStatus.succeeded
        if getattr(status, "failed", None):
            return JobStatus.failed
        if getattr(status, "active", None):
            return JobStatus.running
        return JobStatus.pending

    async def cleanup(self, handle: JobHandle) -> None:
        await self._load_config()
        async with client.ApiClient() as api_client:
            batch_v1 = client.BatchV1Api(api_client)
            try:
                await batch_v1.delete_namespaced_job(
                    name=handle.handle,
                    namespace=self.namespace,
                    propagation_policy="Background",
                )
            except client.ApiException as exc:
                if exc.status != 404:
                    LOG.warning("delete_namespaced_job(%s) → %s", handle.handle, exc)
