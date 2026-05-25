"""SQLAlchemy ORM models.

Importing this package eagerly registers every model class on
``ippon.db.Base.metadata``, which is what Alembic's autogenerate uses to
diff against the live Postgres schema.
"""

from ippon.db import Base
from ippon.models._enums import (
    JobRunnerBackend,
    OrgMemberRole,
    ScanJobStatus,
    ScanTrigger,
    SourceCredentialType,
    SourceProvider,
    WebhookSource,
)
from ippon.models.org import Org, OrgMember
from ippon.models.repository import Repository
from ippon.models.scan_job import ScanJob
from ippon.models.scan_policy import ScanPolicy
from ippon.models.source_connection import SourceConnection
from ippon.models.user import User
from ippon.models.webhook_delivery import WebhookDelivery

__all__ = [
    "Base",
    "JobRunnerBackend",
    "Org",
    "OrgMember",
    "OrgMemberRole",
    "Repository",
    "ScanJob",
    "ScanJobStatus",
    "ScanPolicy",
    "ScanTrigger",
    "SourceConnection",
    "SourceCredentialType",
    "SourceProvider",
    "User",
    "WebhookDelivery",
    "WebhookSource",
]
