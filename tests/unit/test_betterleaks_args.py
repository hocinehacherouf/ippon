"""Pure-helper coverage for the Docker runner's secret-scan stage."""

from __future__ import annotations

from uuid import uuid4

from ippon.scanner.runner.base import ScanJobSpec
from ippon.scanner.runner.docker import (
    _betterleaks_cmd,
    _clone_depth,
    _clone_entrypoint_cmd,
    _secret_scan_network,
)


def _spec(**overrides: object) -> ScanJobSpec:
    base: dict[str, object] = {
        "scan_id": uuid4(),
        "org_id": uuid4(),
        "repo_id": uuid4(),
        "repo_url": "https://github.com/anchore/syft",
        "ref": "HEAD",
        "clone_image": "alpine/git:latest",
        "syft_image": "anchore/syft:latest",
        "grype_image": "anchore/grype:latest",
        "reporter_image": "ippon/backend:dev",
        "grype_db_volume": "ippon_grype_db",
        "network": "ippon_default",
        "callback_url": "http://api:8000/internal/scans/x/callback",
        "callback_secret": "s3cret",
        "secret_scan_image": "ghcr.io/betterleaks/betterleaks:v1.6.0",
    }
    base.update(overrides)
    return ScanJobSpec(**base)  # type: ignore[arg-type]


def test_betterleaks_cmd_redacts_and_never_fails_on_leaks() -> None:
    cmd = _betterleaks_cmd(_spec(secret_history_depth=128))
    assert cmd[0] == "git"
    assert "--redact" in cmd
    assert cmd[cmd.index("--exit-code") + 1] == "0"
    assert "--log-opts=-n 128" in cmd
    assert "/artifacts/secrets.json" in cmd


def test_clone_depth_shallow_when_secrets_disabled() -> None:
    assert _clone_depth(_spec(secret_scan_enabled=False, secret_history_depth=256)) == 1


def test_clone_depth_uses_history_when_enabled() -> None:
    assert _clone_depth(_spec(secret_scan_enabled=True, secret_history_depth=256)) == 256


def test_secret_scan_network_none_by_default() -> None:
    assert _secret_scan_network(_spec(verify_secrets=False)) == "none"


def test_secret_scan_network_stays_isolated_even_when_verifying() -> None:
    # Verification is not wired yet; verify_secrets must NOT open egress.
    assert _secret_scan_network(_spec(verify_secrets=True)) == "none"


def test_clone_entrypoint_uses_depth() -> None:
    assert "--depth=200" in _clone_entrypoint_cmd(200)
