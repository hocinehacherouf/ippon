# syntax=docker/dockerfile:1.7
#
# Reporter image — runs once per scan as the final container in the chain.
# Slim by design: only the deps the reporter actually imports.
#
# Despite copying the whole ``src/ippon`` tree, only the modules under
# ``ippon.reporter``, ``ippon.clickhouse``, ``ippon.config``, and a small
# helper from ``ippon.security`` are imported at runtime. No FastAPI, no
# SQLAlchemy, no Celery.

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app

WORKDIR /app

# Pinned to the same versions we use for the rest of the codebase. If a
# version here drifts from ``pyproject.toml``, things will still work, but
# the test matrix loses meaning.
RUN pip install --no-cache-dir \
        boto3==1.43.14 \
        botocore==1.43.14 \
        clickhouse-connect==1.0.1 \
        httpx==0.28.1 \
        pydantic==2.13.4 \
        pydantic-settings==2.14.1 \
        structlog==25.5.0

COPY src/ippon /app/ippon

ENTRYPOINT ["python", "-m", "ippon.reporter"]
