# syntax=docker/dockerfile:1.7
#
# Single Wolfi-based image for every backend role: API, Celery worker(s),
# beat, and the per-scan reporter container. Each caller (compose service
# or the scan-job runner) supplies its own ``command:`` — the image has
# no ``ENTRYPOINT``/``CMD`` so an unconfigured invocation fails fast.
#
# Pattern lifted from ``groom/backend/Dockerfile`` (Wolfi multi-stage)
# with python-3.12 and ippon's package layout.

FROM cgr.dev/chainguard/wolfi-base@sha256:2f7a5c164eafbdbe46fe1d91bd1ab4c8cb5c2bdbd10641c3d61bd39962384cdb AS builder

RUN apk add --no-cache \
        python-3.12 \
        python-3.12-dev \
        build-base \
        uv

WORKDIR /app

# Sync deps first (cached layer) then copy source.
COPY pyproject.toml uv.lock README.md /app/
COPY src /app/src
# K8sJobRunner reads ``manifests/jobs/scan-job.yaml.j2`` relative to the
# package, so the manifests tree has to land alongside ``src/`` in the
# image. Inline runner test fixtures don't reach this image.
COPY manifests /app/manifests

RUN uv sync --frozen --no-dev --compile-bytecode

# ---

FROM cgr.dev/chainguard/wolfi-base@sha256:2f7a5c164eafbdbe46fe1d91bd1ab4c8cb5c2bdbd10641c3d61bd39962384cdb

# Runtime deps only — no compiler, no headers. ``curl`` is the
# operational probe used by compose / k8s healthchecks (and by us in
# ``docker exec`` debugging).
RUN apk add --no-cache python-3.12 ca-certificates curl git \
    && addgroup -g 1000 -S appgroup \
    && adduser -S appuser -u 1000 -G appgroup

COPY --from=builder --chown=appuser:appgroup /app /app

WORKDIR /app

USER appuser

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONPATH="/app/src" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# No ENTRYPOINT / CMD — every consumer supplies a full command. See
# docker-compose.yml (api/worker-general/worker-scan/beat) and
# ippon.scanner.runner.docker (reporter container).
