"""Unit tests for the pure host-matching helpers in api._bootstrap.

The DB-backed resolution paths (`resolve_scan_target`, anonymous fallback,
ambiguous multi-match) are covered in tests/integration/test_sources.py.
"""

from __future__ import annotations

from ippon.api._bootstrap import _connection_host, _normalize_host, _provider_for_host
from ippon.models import SourceConnection, SourceProvider


def _conn(provider: SourceProvider, base_url: str | None) -> SourceConnection:
    return SourceConnection(provider=provider, base_url=base_url, name="x")


def test_provider_for_host() -> None:
    assert _provider_for_host("github.com") is SourceProvider.github
    assert _provider_for_host("git.acme.com") is SourceProvider.github  # default
    assert _provider_for_host("gitlab.example.com") is SourceProvider.gitlab
    assert _provider_for_host("dev.azure.com") is SourceProvider.azure_devops
    assert _provider_for_host("foo.visualstudio.com") is SourceProvider.azure_devops


def test_normalize_host() -> None:
    assert _normalize_host(None) == ""
    assert _normalize_host("  GitHub.com ") == "github.com"


def test_connection_host_uses_cloud_when_base_url_missing() -> None:
    assert _connection_host(_conn(SourceProvider.github, None)) == "github.com"
    assert _connection_host(_conn(SourceProvider.gitlab, None)) == "gitlab.com"
    assert _connection_host(_conn(SourceProvider.azure_devops, None)) == "dev.azure.com"


def test_connection_host_uses_base_url_host() -> None:
    assert _connection_host(_conn(SourceProvider.github, "https://git.acme.com")) == "git.acme.com"
    # path + port are stripped to the hostname
    assert (
        _connection_host(_conn(SourceProvider.gitlab, "https://gitlab.internal:8443/api/v4"))
        == "gitlab.internal"
    )
