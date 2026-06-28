"""build_scan_job_spec populates secret-scan fields from settings + policy."""

from __future__ import annotations

from uuid import uuid4

from ippon.config import Settings
from ippon.models import Repository, ScanJob, ScanPolicy
from ippon.scanner.pipeline import build_scan_job_spec


def _scan() -> ScanJob:
    return ScanJob(
        id=uuid4(),
        org_id=uuid4(),
        repository_id=uuid4(),
        requested_ref="HEAD",
        callback_secret="s3cret",
    )


def _repo() -> Repository:
    return Repository(clone_url="https://github.com/anchore/syft")


def test_spec_uses_settings_defaults_without_policy() -> None:
    settings = Settings()
    spec = build_scan_job_spec(settings=settings, scan=_scan(), repo=_repo(), policy=None)
    assert spec.secret_scan_enabled is True
    assert spec.verify_secrets is False
    assert spec.secret_history_depth == 256
    assert spec.secret_scan_image == settings.secret_scan_image


def test_spec_honors_policy_overrides() -> None:
    policy = ScanPolicy(
        name="strict",
        org_id=uuid4(),
        secret_scan_enabled=True,
        verify_secrets=True,
        secret_history_depth=50,
    )
    spec = build_scan_job_spec(settings=Settings(), scan=_scan(), repo=_repo(), policy=policy)
    assert spec.verify_secrets is True
    assert spec.secret_history_depth == 50
