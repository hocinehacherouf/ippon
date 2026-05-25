"""Enumerations used across SQLAlchemy models.

These are realised as native Postgres ENUM types via SQLAlchemy's ``Enum``
column type elsewhere; here we keep them as ``StrEnum`` so Python code can
reference them without importing SQLAlchemy machinery.
"""

from __future__ import annotations

import enum


class SourceProvider(enum.StrEnum):
    github = "github"
    gitlab = "gitlab"
    azure_devops = "azure_devops"


class SourceCredentialType(enum.StrEnum):
    pat = "pat"
    oauth = "oauth"
    app = "app"


class OrgMemberRole(enum.StrEnum):
    owner = "owner"
    admin = "admin"
    member = "member"
    viewer = "viewer"


class ScanJobStatus(enum.StrEnum):
    pending = "pending"
    queued = "queued"
    running = "running"
    succeeded = "succeeded"
    failed = "failed"
    cancelled = "cancelled"


class JobRunnerBackend(enum.StrEnum):
    docker = "docker"
    k8s = "k8s"
    inline = "inline"


class WebhookSource(enum.StrEnum):
    github = "github"
    gitlab = "gitlab"
    azure_devops = "azure_devops"


class ScanTrigger(enum.StrEnum):
    manual = "manual"
    webhook = "webhook"
    schedule = "schedule"
