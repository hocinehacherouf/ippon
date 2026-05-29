"""Application settings.

Reads from environment variables and an optional ``.env`` file (when present in
the working directory). All settings are required to have a default in dev so
the test suite can import this module without a live ``.env``.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

JobRunnerBackend = Literal["docker", "k8s", "inline"]


class Settings(BaseSettings):
    """Environment-driven runtime configuration.

    Naming convention: settings keys are lowercase; environment variables are
    the uppercase form (pydantic-settings handles this automatically).
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- connection URLs --------------------------------------------------
    # NB: ``changeme`` is a placeholder. Every secret-shaped default below
    # exists so tests + local dev work out of the box; real values come
    # from ``.env`` (gitignored) or a deployment-time secret manager.
    database_url: str = Field(
        default="postgresql+psycopg://ippon:changeme@localhost:15432/ippon",
        description="SQLAlchemy URL for Postgres (psycopg v3 driver).",
    )
    clickhouse_url: str = Field(
        default="http://ippon:changeme@localhost:18123/ippon",
        description="HTTP URL for ClickHouse, used by clickhouse-connect and asynch.",
    )
    valkey_url: str = Field(
        default="redis://localhost:16379/0",
        description="Celery broker + result backend URL.",
    )

    # --- object storage ---------------------------------------------------
    s3_endpoint_url: str = Field(default="http://localhost:9100")
    s3_bucket: str = Field(default="ippon-sboms")
    rustfs_access_key: str = Field(default="changeme")
    rustfs_secret_key: str = Field(default="changeme")

    # --- app --------------------------------------------------------------
    ippon_dev_token: str = Field(default="changeme")
    ippon_job_runner: JobRunnerBackend = Field(default="docker")
    ippon_secret_key: str = Field(
        default="changeme",
        description="Master key for envelope-encrypting source-provider credentials.",
    )

    # --- HTTP -------------------------------------------------------------
    cors_origins: list[str] = Field(
        default_factory=lambda: [
            "http://localhost:5173",
            "http://localhost:8000",
            "http://127.0.0.1:5173",
            "http://127.0.0.1:8000",
        ],
        description="Origins allowed by the CORS middleware. Defaults cover the dev frontend.",
    )
    # Externally-reachable base URL of the API, used to build the
    # per-connection webhook URLs shown to operators (an org's GitHub/GitLab/
    # AzDO webhook config points here). Distinct from ``callback_base_url``,
    # which is the in-cluster address the reporter posts back to.
    ippon_public_base_url: str = Field(default="http://localhost:8000")

    # NB: webhook secrets are now per-connection (encrypted on the
    # ``source_connections`` row), not global. See ``ippon.security`` +
    # ``api/routes/webhooks``.

    # --- scanner pipeline -------------------------------------------------
    # Container images used by the DockerJobRunner. Each scan can override
    # via the ``ScanJobSpec`` (eg. for a per-org pinned scanner version).
    # Pinned to digests so every scan uses a known runtime — bump these
    # alongside the corresponding compose-stack pins.
    clone_image: str = Field(
        default="alpine/git:latest@sha256:3136372ed3c9e112d5a2620c66a6803e1b0b7f14a428fcbd0c5028bec4256430",
    )
    syft_image: str = Field(
        default="anchore/syft:latest@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6",
    )
    grype_image: str = Field(
        default="anchore/grype:latest@sha256:391bfda62888fb4e98ff5c4c81598f7431a3c1eac3f8519d69d1ff00df247c1d",
    )
    # Single backend image (api / worker / reporter). The DockerJobRunner
    # passes an explicit ``command=["python", "-m", "ippon.reporter"]``
    # since the image has no ENTRYPOINT.
    reporter_image: str = Field(default="ippon/backend:dev")

    # Docker volume holding the Grype CVE DB (populated by grype-db-updater).
    grype_db_volume: str = Field(default="ippon_grype_db")

    # Compose network the reporter joins so it can reach
    # ``clickhouse:8123``, ``rustfs:9000``, and ``api:8000`` by service name.
    scan_job_network: str = Field(default="ippon_default")

    # Per-step resource limits for scan-job containers.
    scan_mem_limit: str = Field(default="2g")
    scan_cpu_count: float = Field(default=1.0)

    # URL the reporter posts its callback to. The host portion must be
    # reachable from inside the scan-job containers (so ``api:8000`` when the
    # API runs in compose, or ``host.docker.internal:8000`` when the API runs
    # on the host).
    callback_base_url: str = Field(default="http://api:8000")

    # --- K8sJobRunner (production path; see M7 manifests) ----------------
    k8s_namespace: str = Field(default="ippon-scans")
    k8s_service_account: str = Field(default="ippon-scanner")
    k8s_grype_db_pvc: str = Field(default="grype-db-shared")
    # Path to an explicit kubeconfig; ``None`` means in-cluster config
    # (production) or the ambient ``~/.kube/config`` (local / CI / kind).
    k8s_kubeconfig: str | None = Field(default=None)
    # Optional kube context to select inside the kubeconfig.
    k8s_context: str | None = Field(default=None)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
