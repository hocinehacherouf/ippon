"""Static validation of the scan-job Jinja2 template.

We don't need a live cluster to verify the manifest shape; rendering with
concrete values and re-parsing as YAML catches typos / Jinja2 errors /
missing variables and asserts the Job has the structure
``K8sJobRunner.submit`` assumes.
"""

from __future__ import annotations

import re
from uuid import UUID, uuid4

import yaml

from ippon.scanner.runner.base import ScanJobSpec
from ippon.scanner.runner.k8s import _render_job_manifest

# Kubernetes resource-quantity grammar (apimachinery). A Docker-style "2g"
# does NOT match (the unit set is case-sensitive: G/Gi, not g) — which is
# exactly the bug this guards against.
_K8S_QUANTITY = re.compile(r"^([+-]?[0-9.]+)([eEinumkKMGTP]*[-+]?[0-9]*)$")


def _spec(
    scan_id: UUID, org_id: UUID, repo_id: UUID, *, secret_scan_enabled: bool = True
) -> ScanJobSpec:
    return ScanJobSpec(
        scan_id=scan_id,
        org_id=org_id,
        repo_id=repo_id,
        repo_url="https://github.com/anchore/syft",
        ref="HEAD",
        clone_image="alpine/git:latest",
        syft_image="anchore/syft:latest",
        grype_image="anchore/grype:latest",
        reporter_image="ippon/reporter:dev",
        grype_db_volume="grype-db-shared",
        network="ippon-scans",
        callback_url="http://api.ippon.svc:8000/internal/scans/x/callback",
        callback_secret="s3cret",
        reporter_env={
            "CLICKHOUSE_URL": "http://ippon:dev@clickhouse:8123/ippon",
            "S3_ENDPOINT_URL": "http://rustfs:9000",
            "S3_BUCKET": "ippon-sboms",
            "AWS_ACCESS_KEY_ID": "k",
            "AWS_SECRET_ACCESS_KEY": "s",
        },
        secret_scan_enabled=secret_scan_enabled,
    )


def test_renders_into_valid_yaml() -> None:
    scan_id = uuid4()
    spec = _spec(scan_id, uuid4(), uuid4())
    job, job_name, secret_name = _render_job_manifest(
        spec,
        namespace="ippon-scans",
        service_account="ippon-scanner",
        grype_db_pvc="grype-db-shared",
    )
    # Sanity: re-serialise + re-parse round-trips cleanly.
    assert yaml.safe_load(yaml.safe_dump(job)) == job
    assert job_name.startswith("ippon-scan-")
    assert secret_name == f"{job_name}-secret"


def test_job_top_level_shape() -> None:
    scan_id = uuid4()
    spec = _spec(scan_id, uuid4(), uuid4())
    job, _job_name, _secret_name = _render_job_manifest(
        spec,
        namespace="ippon-scans",
        service_account="ippon-scanner",
        grype_db_pvc="grype-db-shared",
    )
    assert job["apiVersion"] == "batch/v1"
    assert job["kind"] == "Job"
    assert job["metadata"]["namespace"] == "ippon-scans"
    spec_ = job["spec"]
    assert spec_["ttlSecondsAfterFinished"] == 3600
    assert spec_["backoffLimit"] == 1
    assert spec_["activeDeadlineSeconds"] >= 60


def test_labels_present_on_job_and_pod() -> None:
    scan_id = uuid4()
    org_id = uuid4()
    repo_id = uuid4()
    spec = _spec(scan_id, org_id, repo_id)
    job, _, _ = _render_job_manifest(
        spec,
        namespace="ippon-scans",
        service_account="ippon-scanner",
        grype_db_pvc="grype-db-shared",
    )
    expected = {
        "app": "ippon",
        "ippon.scan-id": str(scan_id),
        "ippon.org-id": str(org_id),
        "ippon.repo-id": str(repo_id),
    }
    for k, v in expected.items():
        assert job["metadata"]["labels"][k] == v
        assert job["spec"]["template"]["metadata"]["labels"][k] == v


def test_init_containers_include_secret_scan_in_order() -> None:
    spec = _spec(uuid4(), uuid4(), uuid4())
    job, _, _ = _render_job_manifest(
        spec,
        namespace="ippon-scans",
        service_account="ippon-scanner",
        grype_db_pvc="grype-db-shared",
    )
    init_names = [c["name"] for c in job["spec"]["template"]["spec"]["initContainers"]]
    assert init_names == ["clone", "syft", "grype", "secret-scan"]


def test_secret_scan_omitted_when_disabled() -> None:
    spec = _spec(uuid4(), uuid4(), uuid4(), secret_scan_enabled=False)
    job, _, _ = _render_job_manifest(
        spec,
        namespace="ippon-scans",
        service_account="ippon-scanner",
        grype_db_pvc="grype-db-shared",
    )
    init_names = [c["name"] for c in job["spec"]["template"]["spec"]["initContainers"]]
    assert init_names == ["clone", "syft", "grype"]


def test_reporter_is_the_only_main_container() -> None:
    spec = _spec(uuid4(), uuid4(), uuid4())
    job, _, _ = _render_job_manifest(
        spec,
        namespace="ippon-scans",
        service_account="ippon-scanner",
        grype_db_pvc="grype-db-shared",
    )
    main = job["spec"]["template"]["spec"]["containers"]
    assert len(main) == 1
    assert main[0]["name"] == "reporter"


def test_reporter_command_is_explicit() -> None:
    """The consolidated backend image has no ENTRYPOINT; the K8s manifest
    must supply an explicit ``command`` so the reporter role is selected."""
    spec = _spec(uuid4(), uuid4(), uuid4())
    job, _, _ = _render_job_manifest(
        spec,
        namespace="ippon-scans",
        service_account="ippon-scanner",
        grype_db_pvc="grype-db-shared",
    )
    reporter = job["spec"]["template"]["spec"]["containers"][0]
    assert reporter["command"] == ["python", "-m", "ippon.reporter"]


def test_reporter_callback_secret_via_secretkeyref() -> None:
    spec = _spec(uuid4(), uuid4(), uuid4())
    job, _, secret_name = _render_job_manifest(
        spec,
        namespace="ippon-scans",
        service_account="ippon-scanner",
        grype_db_pvc="grype-db-shared",
    )
    reporter_env = job["spec"]["template"]["spec"]["containers"][0]["env"]
    secret_refs = [e for e in reporter_env if "valueFrom" in e]
    assert len(secret_refs) == 1
    ref = secret_refs[0]["valueFrom"]["secretKeyRef"]
    assert ref["name"] == secret_name
    assert ref["key"] == "callback_secret"


def test_grype_db_mounted_readonly() -> None:
    spec = _spec(uuid4(), uuid4(), uuid4())
    job, _, _ = _render_job_manifest(
        spec,
        namespace="ippon-scans",
        service_account="ippon-scanner",
        grype_db_pvc="grype-db-shared",
    )
    grype = next(
        c for c in job["spec"]["template"]["spec"]["initContainers"] if c["name"] == "grype"
    )
    mount = next(m for m in grype["volumeMounts"] if m["name"] == "grype-db")
    assert mount["readOnly"] is True

    volumes = job["spec"]["template"]["spec"]["volumes"]
    grype_vol = next(v for v in volumes if v["name"] == "grype-db")
    assert grype_vol["persistentVolumeClaim"]["claimName"] == "grype-db-shared"
    assert grype_vol["persistentVolumeClaim"]["readOnly"] is True


def test_artifacts_volume_is_readonly_in_reporter() -> None:
    spec = _spec(uuid4(), uuid4(), uuid4())
    job, _, _ = _render_job_manifest(
        spec,
        namespace="ippon-scans",
        service_account="ippon-scanner",
        grype_db_pvc="grype-db-shared",
    )
    reporter = job["spec"]["template"]["spec"]["containers"][0]
    mount = next(m for m in reporter["volumeMounts"] if m["name"] == "artifacts")
    assert mount["readOnly"] is True


def test_reporter_env_contains_callback_url_and_scan_ids() -> None:
    scan_id = uuid4()
    org_id = uuid4()
    spec = _spec(scan_id, org_id, uuid4())
    job, _, _ = _render_job_manifest(
        spec,
        namespace="ippon-scans",
        service_account="ippon-scanner",
        grype_db_pvc="grype-db-shared",
    )
    env = {
        e["name"]: e.get("value") for e in job["spec"]["template"]["spec"]["containers"][0]["env"]
    }
    assert env["IPPON_SCAN_ID"] == str(scan_id)
    assert env["IPPON_ORG_ID"] == str(org_id)
    assert env["IPPON_CALLBACK_URL"] == spec.callback_url
    # Reporter-env entries from the spec should be forwarded too.
    assert env["CLICKHOUSE_URL"] == spec.reporter_env["CLICKHOUSE_URL"]
    assert env["S3_BUCKET"] == spec.reporter_env["S3_BUCKET"]


def test_all_resource_quantities_are_valid_k8s() -> None:
    """Every rendered cpu/memory request+limit must be a valid K8s quantity.

    Regression guard for the ``mem_limit='2g'`` bug: a Docker-style memory
    string renders into the Job and the apiserver rejects it with a 400.
    """
    spec = _spec(uuid4(), uuid4(), uuid4())
    job, _, _ = _render_job_manifest(
        spec,
        namespace="ippon-scans",
        service_account="ippon-scanner",
        grype_db_pvc="grype-db-shared",
    )
    pod = job["spec"]["template"]["spec"]
    containers = pod["initContainers"] + pod["containers"]
    assert containers  # sanity
    for c in containers:
        for section in ("requests", "limits"):
            for kind, qty in c["resources"][section].items():
                assert _K8S_QUANTITY.match(str(qty)), f"{c['name']}.{section}.{kind}={qty!r}"
