"""Secret-scan settings + ScanJobSpec fields."""

from __future__ import annotations

from uuid import uuid4

from ippon.config import Settings
from ippon.scanner.runner.base import ScanJobSpec


def test_settings_secret_defaults() -> None:
    s = Settings()
    assert s.secret_scan_enabled is True
    assert s.secret_history_depth == 256
    assert "betterleaks" in s.secret_scan_image


def test_scanjobspec_secret_fields_have_defaults() -> None:
    spec = ScanJobSpec(
        scan_id=uuid4(),
        org_id=uuid4(),
        repo_id=uuid4(),
        repo_url="https://github.com/anchore/syft",
        ref="HEAD",
        clone_image="alpine/git:latest",
        syft_image="anchore/syft:latest",
        grype_image="anchore/grype:latest",
        reporter_image="ippon/backend:dev",
        grype_db_volume="ippon_grype_db",
        network="ippon_default",
        callback_url="http://api:8000/internal/scans/x/callback",
        callback_secret="s3cret",
        secret_scan_image="ghcr.io/betterleaks/betterleaks:v1.6.0",
    )
    assert spec.secret_scan_enabled is True
    assert spec.verify_secrets is False
    assert spec.secret_history_depth == 256

    verify_spec = ScanJobSpec(
        scan_id=uuid4(),
        org_id=uuid4(),
        repo_id=uuid4(),
        repo_url="https://github.com/anchore/syft",
        ref="HEAD",
        clone_image="alpine/git:latest",
        syft_image="anchore/syft:latest",
        grype_image="anchore/grype:latest",
        reporter_image="ippon/backend:dev",
        grype_db_volume="ippon_grype_db",
        network="ippon_default",
        callback_url="http://api:8000/internal/scans/x/callback",
        callback_secret="s3cret",
        secret_scan_image="ghcr.io/betterleaks/betterleaks:v1.6.0",
        secret_scan_enabled=False,
        verify_secrets=True,
        secret_history_depth=50,
    )
    assert verify_spec.secret_scan_enabled is False
    assert verify_spec.verify_secrets is True
    assert verify_spec.secret_history_depth == 50


def test_scanjobspec_secret_scan_image_has_default() -> None:
    spec = ScanJobSpec(
        scan_id=uuid4(),
        org_id=uuid4(),
        repo_id=uuid4(),
        repo_url="https://github.com/anchore/syft",
        ref="HEAD",
        clone_image="alpine/git:latest",
        syft_image="anchore/syft:latest",
        grype_image="anchore/grype:latest",
        reporter_image="ippon/backend:dev",
        grype_db_volume="ippon_grype_db",
        network="ippon_default",
        callback_url="http://api:8000/internal/scans/x/callback",
        callback_secret="s3cret",
    )
    assert "betterleaks" in spec.secret_scan_image
