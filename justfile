# ippon — task runner
# Run `just` (no args) to list recipes.

set shell := ["bash", "-cu"]

# Default target: show available recipes
default:
    @just --list

# --- M1: tooling ---------------------------------------------------------

# Install Python deps into a uv-managed venv
install:
    uv sync --all-extras

# Lint + format check
lint:
    uv run ruff check .
    uv run ruff format --check .

# Auto-fix lint + format
format:
    uv run ruff check --fix .
    uv run ruff format .

# Strict type-check
typecheck:
    uv run mypy

# Run unit tests (excludes integration + k8s by default)
test *args:
    uv run pytest {{args}}

# Run only integration tests (requires `just up`)
test-integration *args:
    uv run pytest -m integration {{args}}

# Run only K8s tests (requires kind/k3d)
test-k8s *args:
    uv run pytest -m k8s {{args}}

# Install pre-commit hooks
hooks:
    uv run pre-commit install

# --- M4: API ------------------------------------------------------------

# Run the FastAPI app locally with auto-reload (binds 0.0.0.0:8000).
api-dev:
    uv run uvicorn ippon.api.main:app --reload --host 0.0.0.0 --port 8000

# --- M5: workers --------------------------------------------------------

# Run a Celery worker locally bound to a named queue.
worker-dev QUEUE='general':
    uv run celery -A ippon.worker.celery_app:celery_app worker \
        --loglevel=INFO --queues={{QUEUE}} --concurrency=2

# Run Celery beat locally.
beat-dev:
    uv run celery -A ippon.worker.celery_app:celery_app beat --loglevel=INFO

# --- M2: docker-compose stack -------------------------------------------

# Bring up the local stack: infra + api + workers + beat. Builds the per-scan
# reporter image first since scan jobs need it on the host daemon. Waits for
# everything to be healthy (and for grype-db-updater to complete).
up:
    @test -f .env || (echo "no .env found — copy .env.example to .env first" && exit 1)
    docker build -f docker/reporter.Dockerfile -t ippon/reporter:dev .
    docker compose up -d --wait

# Stop the local infra stack (data volumes are preserved).
down:
    docker compose down

# Stop and DELETE all persistent volumes. Destructive.
nuke:
    docker compose down -v

# Tail logs from one or more services (no args = all services).
logs *services:
    docker compose logs -f --tail=200 {{services}}

# Show service status and health.
ps:
    docker compose ps

# Re-run the grype DB updater (idempotent).
db-update:
    docker compose run --rm grype-db-updater

# --- M3: migrations -----------------------------------------------------

# Apply Postgres + ClickHouse migrations to head.
migrate:
    uv run alembic upgrade head
    uv run python migrations/clickhouse/apply.py

# Roll back the last Alembic revision (Postgres only).
migrate-down:
    uv run alembic downgrade -1

# Show current Alembic revision.
migrate-current:
    uv run alembic current

# --- M6: scan demo ------------------------------------------------------

DEFAULT_SCAN_REPO := "https://github.com/anchore/syft"
DEFAULT_SCAN_REF  := "HEAD"

# Trigger a scan against the given repo and poll until terminal.
# Examples:
#     just scan
#     just scan https://github.com/anchore/grype
#     just scan https://github.com/foo/bar main
scan repo=DEFAULT_SCAN_REPO ref=DEFAULT_SCAN_REF:
    uv run python -m ippon.scripts.scan {{repo}} {{ref}}

# Build the per-scan reporter image (run once, or after editing the reporter).
build-reporter:
    docker build -f docker/reporter.Dockerfile -t ippon/reporter:dev .

# Show the scan-job containers for a given scan_id.
scan-containers SCAN_ID:
    docker ps -a --filter label=ippon.scan-id={{SCAN_ID}} \
        --format 'table {{{{.Names}}}}\t{{{{.Image}}}}\t{{{{.Status}}}}\t{{{{.Labels}}}}'
