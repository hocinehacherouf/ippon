"""Unit tests for role ordering and org-ref parsing (DB paths → integration)."""

from __future__ import annotations

import uuid

from ippon.api.authz import _resolve_org_ref, role_at_least
from ippon.models import OrgMemberRole


def test_role_at_least_ordering() -> None:
    assert role_at_least(OrgMemberRole.owner, OrgMemberRole.admin)
    assert role_at_least(OrgMemberRole.admin, OrgMemberRole.admin)
    assert not role_at_least(OrgMemberRole.member, OrgMemberRole.admin)
    assert not role_at_least(OrgMemberRole.viewer, OrgMemberRole.member)


def test_resolve_org_ref_uuid_vs_slug() -> None:
    u = uuid.uuid4()
    assert _resolve_org_ref(str(u)) == (u, None)
    assert _resolve_org_ref("acme") == (None, "acme")
