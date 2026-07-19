"""CLI: ``python -m ippon.scripts.bootstrap --org-slug <s> --org-name <n> --owner-email <e>``.

Idempotently creates an ``Org``, a ``User``, and an owner ``OrgMember`` linking
them — each is found-or-created, so re-running with the same arguments is a
no-op after the first run (no duplicate rows, no constraint errors). Uses the
sync engine/session helpers from ``ippon.db`` since this is a one-shot script,
not an async request handler. Used by ``just bootstrap``.
"""

from __future__ import annotations

import argparse
import sys

from sqlalchemy import select

from ippon.config import get_settings
from ippon.db import make_sync_engine, make_sync_session_factory, sync_session_scope
from ippon.models import Org, OrgMember, OrgMemberRole, User


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ippon-bootstrap", description="Create an org + owner membership (idempotent)."
    )
    parser.add_argument("--org-slug", required=True, help="Unique org slug")
    parser.add_argument("--org-name", required=True, help="Org display name")
    parser.add_argument("--owner-email", required=True, help="Email of the owner user")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    email = args.owner_email.strip().lower()
    engine = make_sync_engine(get_settings())
    factory = make_sync_session_factory(engine)
    try:
        with sync_session_scope(factory) as session:
            user = session.scalar(select(User).where(User.email == email))
            if user is None:
                user = User(email=email)
                session.add(user)
                session.flush()

            org = session.scalar(select(Org).where(Org.slug == args.org_slug))
            if org is None:
                org = Org(slug=args.org_slug, name=args.org_name)
                session.add(org)
                session.flush()

            member = session.scalar(
                select(OrgMember).where(OrgMember.org_id == org.id, OrgMember.user_id == user.id)
            )
            if member is None:
                session.add(OrgMember(org_id=org.id, user_id=user.id, role=OrgMemberRole.owner))

            print(f"org {org.slug} ({org.id}) owner={email}")
    finally:
        engine.dispose()
    return 0


if __name__ == "__main__":
    sys.exit(main())
