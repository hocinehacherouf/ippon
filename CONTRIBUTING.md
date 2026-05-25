# Contributing to ippon

Thanks for your interest in ippon. This file covers the dev loop.

## Prerequisites

- Python 3.12
- [`uv`](https://docs.astral.sh/uv/) (package manager)
- [`just`](https://just.systems/) (task runner)
- Docker Desktop or compatible runtime (needed from M2 onward)
- `pnpm` (needed from M8 onward)

## First-time setup

```bash
just install        # creates .venv and syncs deps via uv
just hooks          # installs pre-commit hooks
```

## Daily loop

```bash
just lint           # ruff check + format check
just typecheck      # mypy --strict
just test           # unit tests only (excludes integration + k8s)
just format         # auto-fix lint and reformat
```

Once M2 lands:

```bash
just up             # bring up postgres / clickhouse / valkey / rustfs
just migrate        # apply Postgres + ClickHouse schemas
just scan REPO=https://github.com/anchore/syft
```

## Commit style

[Conventional Commits](https://www.conventionalcommits.org/):
`feat(scanner): add docker job runner`, `fix(api): verify github webhook hmac`,
`chore(deps): bump grype to v0.x.y`, etc.

## CI

The GitHub Actions workflow (`.github/workflows/ci.yml`) needs a single
repository secret to run the integration job:

| Secret name      | Value                                                                                       |
| ---------------- | ------------------------------------------------------------------------------------------- |
| `CI_TEST_SECRET` | Any non-empty string. Used as the password / access key for the ephemeral CI test services. |

Set it under **Settings → Secrets and variables → Actions → New repository
secret**. The secret never leaves the runner, and the services it
configures are torn down at job end.

## Reporting issues

For now, open a GitHub issue with reproduction steps. Security issues should go
through GitHub's private advisory flow.
