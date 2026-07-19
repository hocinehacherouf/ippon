"""Tests for org, member, and me pydantic schemas."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ippon.schemas.org import OrgCreate


def test_org_slug_accepts_valid() -> None:
    """Test that OrgCreate accepts valid slugs."""
    o = OrgCreate(name="Acme Inc", slug="acme-inc")
    assert o.slug == "acme-inc"


def test_org_slug_rejects_invalid() -> None:
    """Test that OrgCreate rejects invalid slugs."""
    for bad in ["Acme", "a b", "under_score", "", "x" * 256, "acme-inc\n"]:
        with pytest.raises(ValidationError):
            OrgCreate(name="x", slug=bad)
