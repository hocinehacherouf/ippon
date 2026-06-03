# ippon

Open-source SBOM generator and CVE scanner for GitHub, GitLab, and Azure DevOps
repositories.

> [!WARNING]
> **Early-stage project — not production ready.**
> ippon is in active scaffold/exploration. APIs, schemas, CLI surface, and
> on-disk formats can change without notice. Auth is a hard-coded dev token,
> there is no multi-tenancy enforcement, and the K8s production path has
> only been smoke-tested. Run it on your laptop or in throwaway environments;
> do not point it at customer repos yet.

ippon watches your repos and runs an ephemeral, per-scan job
(`clone → Syft → Grype → reporter`). Each scan job runs as a Kubernetes Job
in production or as a chain of Docker containers in local dev — both backends
take the same `ScanJobSpec`. Resulting SBOM, dependency graph, and CVE
findings land in ClickHouse + S3-compatible object storage.

## Quickstart

```bash
git clone <repo> ippon && cd ippon
just install
just lint && just typecheck && just test
```

Live local stack (Docker required):

```bash
cp .env.example .env                                  # replace every "changeme"
just up                                               # infra + api + workers + beat + web
just migrate                                          # Postgres + ClickHouse schemas
just scan https://github.com/anchore/syft             # end-to-end demo
open http://localhost:5173/repos                      # UI
open http://localhost:13488                           # ch-ui (ClickHouse admin)
```

> [!NOTE]
> The Postgres image is `postgres:18`. A data volume initialized by an older
> major won't boot on 18 — if `just up` shows Postgres crash-looping after a
> version bump, run `just nuke` to wipe local volumes (destroys local data),
> then `just up && just migrate`.

## Architecture

- **API** (FastAPI, async) — webhook reception, scan enqueue, HMAC-verified
  internal callbacks. Owns Postgres OLTP state.
- **Worker** (Celery on Valkey) — translates a `scan_jobs` row into a
  `ScanJobSpec` and submits it via the configured `JobRunner`.
- **JobRunner** (`Protocol`, three backends) — `k8s` (prod, `kubernetes-asyncio`),
  `docker` (local dev, `aiodocker`), `inline` (unit tests, subprocess).
  Selected by `IPPON_JOB_RUNNER`.
- **Reporter** — runs as the final container of each scan; uploads the SBOM
  to S3, ingests rows into ClickHouse, posts an HMAC-signed callback to
  the API.
- **Web** — Vite + React 19 + TanStack Router/Query/Table + Tailwind v4 +
  small shadcn-style primitives.

## Source connections

An org can register **multiple connections per provider type** — github.com
plus a GitHub Enterprise host, self-hosted GitLab alongside gitlab.com,
several Azure DevOps orgs. Each connection (`POST /sources`) has its own
`base_url`, an encrypted credential (Fernet, keyed by `IPPON_SECRET_KEY`),
and a per-connection webhook secret returned **once** on create.

- **Webhooks** are routed per connection at
  `/webhooks/{github,gitlab,azure-devops}/{connection_id}` and verified
  against that connection's own secret. Paste the `webhook_url` from the
  create response into the provider's webhook config.
- **Scans** resolve to a connection by matching the clone URL host against
  each connection's `base_url`; pass `source_connection_id` to `POST /scans`
  to disambiguate when several connections share a host. With no matching
  connection, a public-repo scan falls back to an anonymous connection, so
  `just scan <public-url>` works with zero configuration.

## Storage

- **Postgres** — orgs, users, source connections, repos, scan policies,
  scan_jobs, webhook deliveries.
- **ClickHouse** — SBOMs (full CycloneDX JSON), dependencies, findings,
  scan metrics, VEX statements. Browser-based query editor (ch-ui) at
  `http://localhost:13488` — on first load enter
  `URL=http://clickhouse:8123` plus the `CLICKHOUSE_*` credentials from
  `.env`.
- **RustFS** (S3-compatible) — canonical CycloneDX blobs at
  `sboms/{org_id}/{repo_id}/{commit_sha}.cdx.json`.

## Project status

The initial scaffold (M1–M9) is complete: tooling, compose stack, migrations,
FastAPI app + webhooks, Celery workers, the full scan pipeline against a
real Docker daemon, a K8s runner with manifest templates, the React UI, and
CI. Live demo against `anchore/syft` runs end-to-end in ~15s.

What's next (post-scaffold) tracks in the issue tracker — VEX UI,
OSV enrichment, orphan-job reaper, real OIDC, notifications, Helm chart.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the dev loop and commit style.

## License

Apache-2.0 — see [LICENSE](./LICENSE).
