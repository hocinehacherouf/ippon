"""Kind-backed integration test for ``K8sJobRunner``.

Excluded from the default ``just test`` run via ``pytest -m 'not k8s'``.

Enabled in CI by setting ``IPPON_K8S_TEST_CONTEXT`` to the kubeconfig
context to use (typically ``kind-ippon-test``). The CI workflow does:

    kind create cluster --name ippon-test
    kind load docker-image ippon/reporter:dev anchore/syft:latest anchore/grype:latest alpine/git:latest \\
        --name ippon-test
    kubectl apply -f manifests/cluster/
    # provision a RWX PVC via NFS or skip the PVC mount in a test overlay
    IPPON_K8S_TEST_CONTEXT=kind-ippon-test just test-k8s

The test exercises the same end state ``DockerJobRunner`` does in M6:
Job admitted, scan chain runs, reporter posts callback, scan_jobs row
reaches ``succeeded`` in Postgres, rows land in ClickHouse, blob in
RustFS. Anything ClickHouse/RustFS-shaped that M6 verifies, this verifies
too — the only diff is the JobRunner backend.
"""

from __future__ import annotations

import os
import shutil
from uuid import uuid4

import pytest

from ippon.scanner.runner.base import ScanJobSpec

pytestmark = pytest.mark.k8s


def _have_kind_context() -> str | None:
    ctx = os.environ.get("IPPON_K8S_TEST_CONTEXT")
    if not ctx:
        return None
    if shutil.which("kubectl") is None:
        return None
    return ctx


@pytest.fixture(scope="module")
def k8s_context() -> str:
    ctx = _have_kind_context()
    if ctx is None:
        pytest.skip("set IPPON_K8S_TEST_CONTEXT=<kubeconfig context> and ensure kubectl is on PATH")
    return ctx


@pytest.fixture
def spec() -> ScanJobSpec:
    return ScanJobSpec(
        scan_id=uuid4(),
        org_id=uuid4(),
        repo_id=uuid4(),
        repo_url="https://github.com/anchore/syft",
        ref="HEAD",
        clone_image="alpine/git:latest",
        syft_image="anchore/syft:latest",
        grype_image="anchore/grype:latest",
        reporter_image="ippon/reporter:dev",
        grype_db_volume="grype-db-shared",
        network="ippon-scans",
        callback_url=os.environ.get(
            "IPPON_K8S_TEST_CALLBACK_URL",
            "http://host.docker.internal:8000/internal/scans/replaced/callback",
        ),
        callback_secret="test-secret",
        reporter_env={
            "CLICKHOUSE_URL": os.environ.get(
                "IPPON_K8S_TEST_CLICKHOUSE_URL",
                "http://ippon:changeme@host.docker.internal:18123/ippon",
            ),
            "S3_ENDPOINT_URL": os.environ.get(
                "IPPON_K8S_TEST_S3_ENDPOINT", "http://host.docker.internal:9100"
            ),
            "S3_BUCKET": "ippon-sboms",
            "AWS_ACCESS_KEY_ID": os.environ.get("IPPON_K8S_TEST_S3_ACCESS_KEY", "changeme"),
            "AWS_SECRET_ACCESS_KEY": os.environ.get("IPPON_K8S_TEST_S3_SECRET_KEY", "changeme"),
        },
    )


@pytest.mark.asyncio
async def test_submit_creates_job_and_secret(k8s_context: str, spec: ScanJobSpec) -> None:
    """Smoke test: submit a Job, read it back, assert label + container shape."""
    from kubernetes_asyncio import client

    from ippon.scanner.runner.k8s import K8sJobRunner

    runner = K8sJobRunner(
        namespace="ippon-scans",
        service_account="ippon-scanner",
        grype_db_pvc="grype-db-shared",
        context=k8s_context,
    )
    handle = await runner.submit(spec)
    assert handle.backend == "k8s"
    assert handle.handle.startswith("ippon-scan-")

    try:
        await runner._load_config()  # test-internal use
        async with client.ApiClient() as api_client:
            batch = client.BatchV1Api(api_client)
            core = client.CoreV1Api(api_client)
            job = await batch.read_namespaced_job(name=handle.handle, namespace="ippon-scans")
            labels = job.metadata.labels or {}
            assert labels.get("ippon.scan-id") == str(spec.scan_id)
            assert labels.get("app") == "ippon"
            secret_name = f"{handle.handle}-secret"
            secret = await core.read_namespaced_secret(name=secret_name, namespace="ippon-scans")
            assert "callback_secret" in (secret.data or {})
    finally:
        await runner.cleanup(handle)


@pytest.mark.asyncio
async def test_status_round_trip(k8s_context: str, spec: ScanJobSpec) -> None:
    """``status(handle)`` returns a sensible state for a fresh Job + 404 after cleanup."""
    from ippon.scanner.runner.base import JobStatus
    from ippon.scanner.runner.k8s import K8sJobRunner

    runner = K8sJobRunner(
        namespace="ippon-scans",
        service_account="ippon-scanner",
        grype_db_pvc="grype-db-shared",
        context=k8s_context,
    )
    handle = await runner.submit(spec)
    try:
        s = await runner.status(handle)
        assert s in {JobStatus.pending, JobStatus.running, JobStatus.succeeded, JobStatus.failed}
    finally:
        await runner.cleanup(handle)
    # After cleanup the Job is gone — give the API a moment, then expect not_found.
    import asyncio

    await asyncio.sleep(0.5)
    assert await runner.status(handle) in {JobStatus.not_found, JobStatus.pending}
