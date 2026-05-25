# syntax=docker/dockerfile:1.7
#
# Celery worker / beat image for ippon.
#
# Two variants are derived from this single image via the compose
# ``command:`` override:
#
#   - worker-general: celery -A ... worker --queues=general
#   - worker-scan:    celery -A ... worker --queues=scan
#   - beat:           celery -A ... beat

FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    UV_LINK_MODE=copy

# uv is the package manager; copy a pinned binary in from the official image.
COPY --from=ghcr.io/astral-sh/uv:0.8.4 /uv /uvx /usr/local/bin/

# Minimal OS deps: ca certs (TLS to RustFS/ClickHouse), curl (compose health
# probes if we ever add one), git (shallow clone helpers used by inline runner
# tests; harmless in worker image).
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Sync deps first (cacheable) then copy source.
COPY pyproject.toml uv.lock README.md /app/
COPY src /app/src
# K8sJobRunner reads manifests/jobs/scan-job.yaml.j2 by path-relative-to-this
# file, so the manifests tree has to land in the image alongside src/.
COPY manifests /app/manifests

RUN uv sync --frozen --no-dev --compile-bytecode

ENV PATH="/app/.venv/bin:$PATH"

# Default to a "general" worker; compose overrides command per-service.
ENTRYPOINT ["celery", "-A", "ippon.worker.celery_app:celery_app"]
CMD ["worker", "--loglevel=INFO", "--queues=general", "--concurrency=2"]
