"""Unit tests for pure helpers in the Docker job runner.

The runner itself needs a live Docker daemon (covered by the integration /
M6 demo path); these cover only the pure functions.
"""

from __future__ import annotations

import pytest

from ippon.scanner.runner.docker import _parse_mem_limit


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2Gi", 2 * 1024**3),  # canonical K8s form used by ScanJobSpec
        ("512Mi", 512 * 1024**2),
        ("1Ki", 1024),
        ("2g", 2 * 1024**3),  # Docker-style back-compat
        ("256m", 256 * 1024**2),
        ("1024", 1024),  # plain bytes
        ("0", 0),
        ("", 0),
        ("1.5Gi", int(1.5 * 1024**3)),  # fractional
    ],
)
def test_parse_mem_limit(value: str, expected: int) -> None:
    assert _parse_mem_limit(value) == expected
