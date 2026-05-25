"""Smoke test: the package imports and exposes a version."""

import re

import ippon


def test_package_has_version() -> None:
    assert isinstance(ippon.__version__, str)
    assert re.match(r"^\d+\.\d+\.\d+", ippon.__version__)
