"""Inline runner clone command honours the configured history depth."""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from ippon.scanner.runner.base import ScanJobSpec
from ippon.scanner.runner.inline import InlineJobRunner


def _spec(**overrides: object) -> ScanJobSpec:
    base: dict[str, object] = dict(
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
    base.update(overrides)
    return ScanJobSpec(**base)  # type: ignore[arg-type]


def test_clone_cmd_uses_history_depth_when_enabled() -> None:
    cmd = InlineJobRunner._clone_cmd(_spec(secret_history_depth=64), Path("/tmp/ws"))
    assert "--depth=64" in cmd


def test_clone_cmd_shallow_when_secrets_disabled() -> None:
    cmd = InlineJobRunner._clone_cmd(_spec(secret_scan_enabled=False), Path("/tmp/ws"))
    assert "--depth=1" in cmd


def test_clone_cmd_adds_branch_for_non_head_ref() -> None:
    cmd = InlineJobRunner._clone_cmd(_spec(ref="main"), Path("/tmp/ws"))
    assert "--branch" in cmd
    assert "main" in cmd
