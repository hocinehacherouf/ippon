# ippon

Open-source SBOM generator and CVE scanner for GitHub, GitLab, and Azure DevOps
repositories.

ippon watches your repos, runs an isolated ephemeral scan job per scan
(`clone → Syft → Grype → reporter`), and stores the resulting SBOM, dependency
graph, and CVE findings in ClickHouse and S3-compatible object storage. Scan
jobs run as Kubernetes Jobs in production and as a chain of Docker containers
in local dev — driven by the same `ScanJobSpec` either way.

## Quickstart

> The full local-dev path lands incrementally — see the **Status** section
> below for what works today.

```bash
git clone <repo> ippon && cd ippon
just install              # uv sync
just lint && just typecheck && just test
```

Live local dev:

```bash
just up                                                    # M2 — infra + api + workers + beat + web
just migrate                                               # M3 — Postgres + ClickHouse
just scan https://github.com/anchore/syft                  # M6 — end-to-end demo
open http://localhost:5173/repos                           # M8 — UI
```

## Architecture

- **API** (FastAPI, async) — webhook reception, scan enqueue, internal
  callbacks. Owns Postgres OLTP state.
- **Worker** (Celery on Valkey) — translates a `scan_jobs` row into a
  `ScanJobSpec` and submits it via the configured `JobRunner`.
- **JobRunner** (Protocol, three backends) — `k8s` (prod), `docker` (local
  dev), `inline` (unit tests). Selected by `IPPON_JOB_RUNNER`.
- **Reporter** — runs inside the scan job's main container; uploads the SBOM,
  ingests rows into ClickHouse, and posts an HMAC-signed callback to the API.
- **Web** — Vite + React 18 + TanStack + Tailwind + shadcn/ui.

## Storage

- **Postgres** — orgs, users, source connections, repos, scan policies,
  scan_jobs, webhook deliveries.
- **ClickHouse** — SBOMs (full CycloneDX JSON), dependencies, findings,
  scan metrics, VEX statements.
- **RustFS** (S3-compatible) — canonical CycloneDX blobs at
  `sboms/{org_id}/{repo_id}/{commit_sha}.cdx.json`.

## Status

- ✅ **M1 — Tooling + skeleton**: `uv`/`ruff`/`mypy --strict`/`pytest`/
  `pre-commit`/`just` wired up; empty package layout green.
- ✅ **M2 — docker-compose stack**: postgres 16, clickhouse 24, valkey 8,
  rustfs (S3-compatible) all healthy; grype CVE DB hydrated into a named
  volume by a one-shot `grype-db-updater` service. `just up` / `just down` /
  `just logs` / `just db-update` wired.
- ✅ **M3 — Database + models + migrations**: SQLAlchemy 2.0 typed models
  for 8 Postgres tables (orgs, users, org_members, source_connections,
  repositories, scan_policies, scan_jobs, webhook_deliveries); Alembic
  wired (URL injected from `Settings.database_url`); ClickHouse schema for
  `sboms`, `dependencies`, `findings`, `scan_metrics`, `vex_statements`
  applied by an idempotent versioned applier. `just migrate` brings both
  DBs from empty → head; re-running is a no-op.
- ✅ **M4 — FastAPI skeleton**: app factory with lifespan (DB engine, async
  Valkey client, sync ClickHouse client), CORS, request-ID middleware,
  structured error handlers. Routes for `/health`, `/ready` (probes PG +
  CH + Valkey + RustFS), `/orgs`, `/sources`, `/repos`, `/scans`, `/auth`
  (501 placeholders, bearer-auth-gated). Webhook receivers for GitHub
  (HMAC-SHA256), GitLab (X-Gitlab-Token), Azure DevOps (basic auth) —
  verify signatures, dedupe via `webhook_deliveries`. `just api-dev`
  wired.
- ✅ **M5 — Celery + worker skeleton**: Celery app with `general` (default)
  and `scan` queues on Valkey, JSON serialization, UTC, beat schedule stub.
  Containerized via `docker/worker.Dockerfile` — `worker-general`,
  `worker-scan` (mounts grype DB read-only), and `beat` all run in compose
  and wait on `grype-db-updater` completion. `POST /admin/ping/{queue}` →
  `GET /admin/ping/{task_id}` round-trip verifies API ↔ broker ↔ worker
  ↔ result backend. `just worker-dev` / `just beat-dev` available for local
  iteration.
- ✅ **M6 — Scanner pipeline via `JobRunner`**: backend-agnostic
  `ScanJobSpec` + `JobHandle` + `JobRunner` Protocol. `DockerJobRunner`
  drives a 4-container chain (clone → syft → grype → reporter) on the
  host Docker daemon; the worker-scan container talks to it via the
  bind-mounted socket. `InlineJobRunner` runs the same steps via
  subprocess (test-only). The reporter ingests CH rows + uploads the
  SBOM to RustFS + posts an HMAC-signed callback to
  `/internal/scans/{scan_id}/callback`. The Celery `scan.run_scan` task
  is the orchestrator; the API's `POST /scans` registers the repo on
  first sight and enqueues. `just scan <url>` end-to-end:
  https://github.com/anchore/syft → succeeded in ~15s, 2341 deps + 6914
  findings + 2.1 MB CycloneDX JSON in CH and RustFS.
- ✅ **M7 — `K8sJobRunner` + manifest templates**: production path
  delivered. Jinja2 template at `manifests/jobs/scan-job.yaml.j2` renders
  into a `batch/v1.Job` (init containers: clone → syft → grype, main:
  reporter), with per-scan labels (`ippon.scan-id`, `ippon.org-id`,
  `ippon.repo-id`), `ttlSecondsAfterFinished=3600`, `backoffLimit=1`,
  per-step resource requests/limits, RWX `grype-db-shared` PVC mounted
  read-only into the grype step, and an HMAC secret injected via a
  per-Job Secret owned by the Job (cascades on cleanup). Supporting
  cluster manifests under `manifests/cluster/`: `namespace.yaml`,
  `scanner-rbac.yaml` (ServiceAccount + namespace-scoped Role for jobs +
  pods + secrets only), `grype-db-pvc.yaml`, `grype-db-updater-cronjob.yaml`
  (every 6h, `concurrencyPolicy=Replace`). `K8sJobRunner` uses
  `kubernetes-asyncio` with in-cluster + kubeconfig auto-detect. Selected
  by `IPPON_JOB_RUNNER=k8s`. Template rendering covered by 9 unit tests
  in default `just test`; live kind-backed integration test in
  `tests/k8s/` is opt-in via `@pytest.mark.k8s` + `IPPON_K8S_TEST_CONTEXT`
  env, deferred to M9 CI.
- ✅ **M8 — Frontend skeleton**: Vite 6 + React 19 + TS strict + TanStack
  Router (file-based) + TanStack Query + TanStack Table + Tailwind v4 +
  small shadcn-style UI primitives. Two pages backed by real API data:
  `/repos` (TanStack Table listing every registered repo with last-scan
  status, finished-at, duration, link to detail) and `/scans/$id`
  (status badge, scan header card with backend/ref/commit/syft/grype
  versions, paginated findings table with severity badges and filter
  pills). Real API surface lit up to feed the UI: `GET /repos` with
  last-scan join from Postgres, `GET /scans/{id}/findings` paginated +
  severity-filtered from ClickHouse. Compose `web` service runs
  `vite dev` on :5173 with proxy → `api:8000`. `orval.config.ts` ready
  to regenerate the typed client from the live OpenAPI spec.
- ✅ **M9 — CI**: `.github/workflows/ci.yml` runs on every PR + push to
  main. Required jobs: `python-lint` (ruff), `python-typecheck` (mypy
  strict), `python-test-unit` (pytest defaults), `python-test-integration`
  (Postgres/ClickHouse/Valkey/RustFS via `services:` block, alembic + CH
  applier, then `pytest -m integration`), `web-lint-build`
  (`tsc --noEmit` + `vite build`). Aggregate gate `ci-success`. Opt-in
  `k8s-test` job uses `helm/kind-action`, gated on `ci:k8s` PR label or
  `workflow_dispatch`. uv + pnpm caches wired. Concurrency cancellation
  on PR re-pushes.

## License

Apache-2.0 — see [LICENSE](./LICENSE).
