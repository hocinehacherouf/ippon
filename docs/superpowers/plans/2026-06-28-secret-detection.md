# Secret Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a betterleaks-based `secret-scan` stage to the scan pipeline that scans a capped slice of git history, stores redacted findings in ClickHouse, and surfaces them through the API and Web UI.

**Architecture:** A new container stage runs between Grype and the reporter (`clone → syft → grype → secret-scan → reporter`), mirroring how Syft/Grype already work — an upstream tool image reads the shared `/workspace` volume and writes a JSON artifact the reporter ingests. The clone stage is deepened to a capped depth so history is available. Detection is detect-only by default; live verification is opt-in per scan policy. Raw secret values are never persisted: betterleaks runs with `--redact` so only masked values ever leave the scan container.

**Tech Stack:** Python 3.12 (FastAPI, SQLAlchemy 2.0, Celery, clickhouse-connect, aiodocker, kubernetes-asyncio, Jinja2), ClickHouse, Postgres/Alembic, betterleaks (`ghcr.io/betterleaks/betterleaks`), React 19 + TanStack Router/Query/Table + Tailwind.

Design spec: `docs/superpowers/specs/2026-06-28-secret-detection-design.md`.

## Global Constraints

- Python `>=3.12,<3.13`. Every new module starts with `from __future__ import annotations`.
- Ruff: line-length 100, double-quote style, isort import ordering, pep8-naming. mypy `strict` over `src/ippon`, `tests`, `migrations/clickhouse/apply.py`.
- **Security invariant (non-negotiable):** a raw secret value must NEVER be written to ClickHouse, S3, the callback payload, or any log. betterleaks runs with `--redact`; only masked `Match`/`Secret` strings are ever read or stored.
- **betterleaks exit code:** always pass `--exit-code 0` so "leaks found" is a successful exit; any non-zero exit is a genuine tool error.
- betterleaks image is pinned by tag in `Settings` (default `ghcr.io/betterleaks/betterleaks:v1.6.0`; pin to a `@sha256:` digest before production, matching the other scanner images).
- Capped history depth default: **256** commits, everywhere (Settings, ScanJobSpec, scan_policies, clone depth).
- TDD per step: write failing test → run it red → implement minimal code → run it green → commit. Frequent commits.
- Commands: tests `uv run pytest`; lint `uv run ruff check . && uv run ruff format --check .`; types `uv run mypy`; web typecheck `pnpm --dir web lint`.
- Every commit message ends with the trailer: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
- Alembic current head is `9539a84c02e4`.

## File Structure

**Created:**
- `migrations/clickhouse/0002_secret_findings.sql` — `secret_findings` table + `scan_metrics` secret columns.
- `alembic/versions/<generated>_add_secret_scan_policy_columns.py` — Postgres `scan_policies` columns.
- `src/ippon/schemas/secret.py` — `SecretFinding`, `SecretFindingPage` API models.
- `tests/fixtures/betterleaks-report.json` — redacted betterleaks JSON sample for ingest tests.
- `tests/unit/test_secret_findings_migration.py`, `tests/unit/test_secret_policy_model.py`, `tests/unit/test_secret_config_spec.py`, `tests/unit/test_secret_pipeline.py`, `tests/unit/test_secret_ingest.py`, `tests/unit/test_betterleaks_args.py`, `tests/unit/test_inline_clone_cmd.py`, `tests/unit/test_secrets_endpoint.py`.

**Modified:**
- `src/ippon/config.py` — Settings: `secret_scan_image`, `secret_scan_enabled`, `secret_history_depth`.
- `src/ippon/scanner/runner/base.py` — `ScanJobSpec` secret fields.
- `src/ippon/models/scan_policy.py` — three secret columns.
- `src/ippon/scanner/pipeline.py` — `build_scan_job_spec` accepts a policy.
- `src/ippon/worker/tasks/scan.py` — resolve the effective scan policy and pass it.
- `src/ippon/reporter/ingest.py` — secret parser + insert + `IngestResult` fields.
- `src/ippon/reporter/__main__.py` — wire `secrets_path` + payload counts.
- `src/ippon/schemas/scan.py` — `CallbackPayload` secret counts.
- `src/ippon/scanner/runner/docker.py` — secret-scan step, clone depth, pure helpers.
- `src/ippon/scanner/runner/inline.py` — clone depth via a pure helper.
- `manifests/jobs/scan-job.yaml.j2` — secret-scan init container + clone depth.
- `src/ippon/scanner/runner/k8s.py` — pass new template vars.
- `tests/unit/test_k8s_template.py` — update init-container expectations.
- `src/ippon/api/routes/scans.py` — `GET /scans/{id}/secrets`.
- `web/src/api/client.ts` — `SecretFinding` + `listSecrets`.
- `web/src/components/ui/badge.tsx` — `VerifiedBadge`.
- `web/src/routes/scans/$id.tsx` — Secrets table.

---

### Task 1: ClickHouse `secret_findings` migration

**Files:**
- Create: `migrations/clickhouse/0002_secret_findings.sql`
- Test: `tests/unit/test_secret_findings_migration.py`

**Interfaces:**
- Consumes: the existing `migrations/clickhouse/apply.py` helpers `split_statements()` and `discover_migrations()`.
- Produces: a ClickHouse `secret_findings` table and two new `scan_metrics` columns (`secret_finding_count`, `verified_secret_count`), both consumed by Task 5's reporter ingest and Task 9's API.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_secret_findings_migration.py`:

```python
"""The 0002 ClickHouse migration is discoverable and well-formed."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parents[2]
MIGRATION = REPO_ROOT / "migrations" / "clickhouse" / "0002_secret_findings.sql"


def _load_apply() -> ModuleType:
    path = REPO_ROOT / "migrations" / "clickhouse" / "apply.py"
    spec = importlib.util.spec_from_file_location("ch_apply", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_migration_0002_is_discovered() -> None:
    apply = _load_apply()
    versions = {v for v, _ in apply.discover_migrations()}
    assert 2 in versions


def test_migration_0002_statements_are_wellformed() -> None:
    apply = _load_apply()
    stmts = apply.split_statements(MIGRATION.read_text(encoding="utf-8"))
    assert all(s.strip() for s in stmts), "no empty statements"
    assert any("CREATE TABLE IF NOT EXISTS secret_findings" in s for s in stmts)
    assert any("ADD COLUMN IF NOT EXISTS secret_finding_count" in s for s in stmts)
    assert any("ADD COLUMN IF NOT EXISTS verified_secret_count" in s for s in stmts)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_secret_findings_migration.py -v`
Expected: FAIL — `test_migration_0002_is_discovered` finds no version 2; the file read raises `FileNotFoundError`.

- [ ] **Step 3: Write the migration**

Create `migrations/clickhouse/0002_secret_findings.sql`:

```sql
-- ippon ClickHouse schema v2 — secret detection.
--
-- Adds the secret_findings table (one row per detected secret) and two
-- secret aggregate columns on scan_metrics. Applied by apply.py after 0001.
--
-- Security: ``match`` holds the betterleaks --redact output only. No raw
-- secret value is ever stored here.

-- ----------------------------------------------------------------------
-- secret_findings — one row per (scan, detected secret).
-- ----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS secret_findings (
    scan_id            UUID,
    org_id             UUID,
    repo_id            UUID,
    commit_sha         String,                    -- commit the secret was found in
    rule_id            LowCardinality(String),    -- betterleaks RuleID
    description        String,
    file               String,
    start_line         UInt32,
    end_line           UInt32,
    match              String CODEC(ZSTD(3)),     -- redacted match line
    fingerprint        String,                    -- commit:file:ruleID:startline
    author             String,
    email              String,
    committed_at       Nullable(DateTime),
    tags               Array(String),
    verified           Bool,                      -- true only if validated live
    validation_status  LowCardinality(String),    -- verified/unverified/unknown/error
    is_historical      Bool,                      -- commit_sha != HEAD
    scanned_at         DateTime
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(scanned_at)
ORDER BY (org_id, repo_id, verified, scan_id);

-- ----------------------------------------------------------------------
-- scan_metrics — secret aggregates alongside the dependency/CVE counts.
-- ----------------------------------------------------------------------
ALTER TABLE scan_metrics ADD COLUMN IF NOT EXISTS secret_finding_count UInt32 DEFAULT 0;
ALTER TABLE scan_metrics ADD COLUMN IF NOT EXISTS verified_secret_count UInt32 DEFAULT 0;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_secret_findings_migration.py -v`
Expected: PASS (2 passed).

- [ ] **Step 5: Commit**

```bash
git add migrations/clickhouse/0002_secret_findings.sql tests/unit/test_secret_findings_migration.py
git commit -m "feat(clickhouse): add secret_findings table and scan_metrics secret columns

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Settings + ScanJobSpec secret fields

**Files:**
- Modify: `src/ippon/config.py` (after the `grype_db_volume` setting, ~line 104)
- Modify: `src/ippon/scanner/runner/base.py` (`ScanJobSpec`, after `cpu_count`, ~line 93)
- Test: `tests/unit/test_secret_config_spec.py`

**Interfaces:**
- Produces:
  - `Settings.secret_scan_image: str`, `Settings.secret_scan_enabled: bool`, `Settings.secret_history_depth: int`.
  - `ScanJobSpec` fields `secret_scan_image: str`, `secret_scan_enabled: bool = True`, `verify_secrets: bool = False`, `secret_history_depth: int = 256`. These are consumed by Tasks 4, 6, 7, 8.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_secret_config_spec.py`:

```python
"""Secret-scan settings + ScanJobSpec fields."""

from __future__ import annotations

from uuid import uuid4

from ippon.config import Settings
from ippon.scanner.runner.base import ScanJobSpec


def test_settings_secret_defaults() -> None:
    s = Settings()
    assert s.secret_scan_enabled is True
    assert s.secret_history_depth == 256
    assert "betterleaks" in s.secret_scan_image


def test_scanjobspec_secret_fields_have_defaults() -> None:
    spec = ScanJobSpec(
        scan_id=uuid4(),
        org_id=uuid4(),
        repo_id=uuid4(),
        repo_url="https://github.com/anchore/syft",
        ref="HEAD",
        clone_image="alpine/git:latest",
        syft_image="anchore/syft:latest",
        grype_image="anchore/grype:latest",
        reporter_image="ippon/backend:dev",
        grype_db_volume="ippon_grype_db",
        network="ippon_default",
        callback_url="http://api:8000/internal/scans/x/callback",
        callback_secret="s3cret",
        secret_scan_image="ghcr.io/betterleaks/betterleaks:v1.6.0",
    )
    assert spec.secret_scan_enabled is True
    assert spec.verify_secrets is False
    assert spec.secret_history_depth == 256

    verify_spec = ScanJobSpec(
        scan_id=uuid4(),
        org_id=uuid4(),
        repo_id=uuid4(),
        repo_url="https://github.com/anchore/syft",
        ref="HEAD",
        clone_image="alpine/git:latest",
        syft_image="anchore/syft:latest",
        grype_image="anchore/grype:latest",
        reporter_image="ippon/backend:dev",
        grype_db_volume="ippon_grype_db",
        network="ippon_default",
        callback_url="http://api:8000/internal/scans/x/callback",
        callback_secret="s3cret",
        secret_scan_image="ghcr.io/betterleaks/betterleaks:v1.6.0",
        secret_scan_enabled=False,
        verify_secrets=True,
        secret_history_depth=50,
    )
    assert verify_spec.secret_scan_enabled is False
    assert verify_spec.verify_secrets is True
    assert verify_spec.secret_history_depth == 50
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_secret_config_spec.py -v`
Expected: FAIL — `Settings` has no `secret_scan_enabled`; `ScanJobSpec.__init__` rejects `secret_scan_image`.

- [ ] **Step 3: Add the Settings fields**

In `src/ippon/config.py`, immediately after the `grype_db_volume` field (~line 104), add:

```python
    # --- secret scanning (betterleaks) -----------------------------------
    # Pinned betterleaks image for the secret-scan stage. Pin to a
    # ``@sha256:`` digest before production, like the other scanner images.
    secret_scan_image: str = Field(
        default="ghcr.io/betterleaks/betterleaks:v1.6.0",
    )
    # Global default for whether the secret-scan stage runs. A per-repo /
    # per-org ScanPolicy can override this. When false the stage is skipped
    # and the clone stays shallow.
    secret_scan_enabled: bool = Field(default=True)
    # How many commits of history to clone + scan (``--log-opts="-n N"``).
    secret_history_depth: int = Field(default=256)
```

- [ ] **Step 4: Add the ScanJobSpec fields**

In `src/ippon/scanner/runner/base.py`, inside `ScanJobSpec`, after the `cpu_count` field (~line 93) and before `active_deadline_seconds`, add:

```python
    # --- secret scanning -------------------------------------------------
    # betterleaks image for the secret-scan stage.
    secret_scan_image: str = "ghcr.io/betterleaks/betterleaks:v1.6.0"
    # Whether to run the secret-scan stage at all (skips the stage + keeps
    # the clone shallow when false).
    secret_scan_enabled: bool = True
    # Whether to attempt live verification (needs egress; off by default).
    verify_secrets: bool = False
    # Commits of history to clone + scan.
    secret_history_depth: int = 256
```

> Note: `secret_scan_image` has a default so existing `ScanJobSpec(...)` call sites (e.g. the k8s template test helper) keep working; `build_scan_job_spec` always sets it explicitly from `Settings`.

- [ ] **Step 5: Run test + lint + types**

Run: `uv run pytest tests/unit/test_secret_config_spec.py -v && uv run ruff check src/ippon/config.py src/ippon/scanner/runner/base.py && uv run mypy`
Expected: tests PASS; ruff clean; mypy `Success`.

- [ ] **Step 6: Commit**

```bash
git add src/ippon/config.py src/ippon/scanner/runner/base.py tests/unit/test_secret_config_spec.py
git commit -m "feat(scanner): add secret-scan settings and ScanJobSpec fields

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: scan_policies secret columns

**Files:**
- Modify: `src/ippon/models/scan_policy.py` (after `enabled`, ~line 41)
- Create: `alembic/versions/<generated>_add_secret_scan_policy_columns.py` (via `alembic revision`)
- Test: `tests/unit/test_secret_policy_model.py`

**Interfaces:**
- Produces: `ScanPolicy.secret_scan_enabled: bool`, `ScanPolicy.verify_secrets: bool`, `ScanPolicy.secret_history_depth: int`. Consumed by Task 4.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_secret_policy_model.py`:

```python
"""ScanPolicy secret-scan columns + defaults."""

from __future__ import annotations

from ippon.models import ScanPolicy


def test_scan_policy_has_secret_columns() -> None:
    cols = ScanPolicy.__table__.columns
    assert "secret_scan_enabled" in cols
    assert "verify_secrets" in cols
    assert "secret_history_depth" in cols


def test_scan_policy_secret_column_defaults() -> None:
    cols = ScanPolicy.__table__.columns
    assert cols["secret_scan_enabled"].default.arg is True
    assert cols["verify_secrets"].default.arg is False
    assert cols["secret_history_depth"].default.arg == 256
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_secret_policy_model.py -v`
Expected: FAIL — `"secret_scan_enabled" in cols` is False.

- [ ] **Step 3: Add the model columns**

In `src/ippon/models/scan_policy.py`, after the `enabled` column (~line 41), add:

```python
    # --- secret scanning -------------------------------------------------
    secret_scan_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    verify_secrets: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    secret_history_depth: Mapped[int] = mapped_column(
        Integer, nullable=False, default=256, server_default="256"
    )
```

(`Boolean` and `Integer` are already imported at the top of the file.)

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_secret_policy_model.py -v`
Expected: PASS (2 passed).

- [ ] **Step 5: Generate + fill the Alembic migration**

Run: `uv run alembic revision -m "add secret scan policy columns"`
This creates `alembic/versions/<rev>_add_secret_scan_policy_columns.py` with the correct `down_revision = '9539a84c02e4'`. Replace its `upgrade()`/`downgrade()` bodies with:

```python
def upgrade() -> None:
    op.add_column(
        "scan_policies",
        sa.Column("secret_scan_enabled", sa.Boolean(), nullable=False, server_default="true"),
    )
    op.add_column(
        "scan_policies",
        sa.Column("verify_secrets", sa.Boolean(), nullable=False, server_default="false"),
    )
    op.add_column(
        "scan_policies",
        sa.Column("secret_history_depth", sa.Integer(), nullable=False, server_default="256"),
    )


def downgrade() -> None:
    op.drop_column("scan_policies", "secret_history_depth")
    op.drop_column("scan_policies", "verify_secrets")
    op.drop_column("scan_policies", "secret_scan_enabled")
```

(Ensure `import sqlalchemy as sa` and `from alembic import op` are present — the revision template includes them.)

- [ ] **Step 6: Verify model tests + lint + types still pass**

Run: `uv run pytest tests/unit/test_secret_policy_model.py tests/unit/test_models.py -v && uv run ruff check . && uv run mypy`
Expected: all PASS; `test_no_stray_tables` still sees 8 tables (no new table added); ruff clean; mypy `Success`.

- [ ] **Step 7: Commit**

```bash
git add src/ippon/models/scan_policy.py alembic/versions/*_add_secret_scan_policy_columns.py tests/unit/test_secret_policy_model.py
git commit -m "feat(models): add secret-scan policy columns + migration

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: build_scan_job_spec policy wiring

**Files:**
- Modify: `src/ippon/scanner/pipeline.py`
- Modify: `src/ippon/worker/tasks/scan.py`
- Test: `tests/unit/test_secret_pipeline.py`

**Interfaces:**
- Consumes: `Settings` secret fields (Task 2), `ScanPolicy` secret columns (Task 3), `ScanJobSpec` secret fields (Task 2).
- Produces: `build_scan_job_spec(*, settings, scan, repo, policy: ScanPolicy | None = None) -> ScanJobSpec` populating the secret fields. The worker resolves the effective policy (repo override, then org default) and passes it.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_secret_pipeline.py`:

```python
"""build_scan_job_spec populates secret-scan fields from settings + policy."""

from __future__ import annotations

from uuid import uuid4

from ippon.config import Settings
from ippon.models import Repository, ScanJob, ScanPolicy
from ippon.scanner.pipeline import build_scan_job_spec


def _scan() -> ScanJob:
    return ScanJob(
        id=uuid4(),
        org_id=uuid4(),
        repository_id=uuid4(),
        requested_ref="HEAD",
        callback_secret="s3cret",
    )


def _repo() -> Repository:
    return Repository(clone_url="https://github.com/anchore/syft")


def test_spec_uses_settings_defaults_without_policy() -> None:
    settings = Settings()
    spec = build_scan_job_spec(settings=settings, scan=_scan(), repo=_repo(), policy=None)
    assert spec.secret_scan_enabled is True
    assert spec.verify_secrets is False
    assert spec.secret_history_depth == 256
    assert spec.secret_scan_image == settings.secret_scan_image


def test_spec_honors_policy_overrides() -> None:
    policy = ScanPolicy(
        name="strict",
        org_id=uuid4(),
        secret_scan_enabled=True,
        verify_secrets=True,
        secret_history_depth=50,
    )
    spec = build_scan_job_spec(settings=Settings(), scan=_scan(), repo=_repo(), policy=policy)
    assert spec.verify_secrets is True
    assert spec.secret_history_depth == 50
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_secret_pipeline.py -v`
Expected: FAIL — `build_scan_job_spec()` has no `policy` keyword.

- [ ] **Step 3: Update build_scan_job_spec**

In `src/ippon/scanner/pipeline.py`, update the import and the function. Change the import line:

```python
from ippon.models import Repository, ScanJob, ScanPolicy
```

Change the signature to add `policy`, and add the secret fields to the returned `ScanJobSpec`:

```python
def build_scan_job_spec(
    *,
    settings: Settings,
    scan: ScanJob,
    repo: Repository,
    policy: ScanPolicy | None = None,
) -> ScanJobSpec:
```

Just before the `return ScanJobSpec(...)`, compute the secret flags:

```python
    # Secret-scan flags: a ScanPolicy (repo override, else org default) wins;
    # otherwise fall back to global Settings. verify is policy-only — off
    # unless a policy explicitly opts in.
    secret_scan_enabled = (
        policy.secret_scan_enabled if policy is not None else settings.secret_scan_enabled
    )
    verify_secrets = policy.verify_secrets if policy is not None else False
    secret_history_depth = (
        policy.secret_history_depth if policy is not None else settings.secret_history_depth
    )
```

Then add these keyword args to the `return ScanJobSpec(...)` call (after `cpu_count=settings.scan_cpu_count,`):

```python
        secret_scan_image=settings.secret_scan_image,
        secret_scan_enabled=secret_scan_enabled,
        verify_secrets=verify_secrets,
        secret_history_depth=secret_history_depth,
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_secret_pipeline.py -v`
Expected: PASS (2 passed).

- [ ] **Step 5: Wire the worker to resolve + pass the policy**

In `src/ippon/worker/tasks/scan.py`, update the model import:

```python
from ippon.models import Repository, ScanJob, ScanJobStatus, ScanPolicy
```

Add `from sqlalchemy import select` to the imports. Then, inside `run_scan`, replace the single line `spec = build_scan_job_spec(settings=settings, scan=scan, repo=repo)` with:

```python
            policy = session.execute(
                select(ScanPolicy).where(ScanPolicy.repository_id == repo.id)
            ).scalars().first()
            if policy is None:
                policy = session.execute(
                    select(ScanPolicy).where(
                        ScanPolicy.org_id == repo.org_id,
                        ScanPolicy.repository_id.is_(None),
                    )
                ).scalars().first()
            spec = build_scan_job_spec(settings=settings, scan=scan, repo=repo, policy=policy)
```

- [ ] **Step 6: Run full suite + lint + types**

Run: `uv run pytest tests/unit/test_secret_pipeline.py -v && uv run ruff check src/ippon/scanner/pipeline.py src/ippon/worker/tasks/scan.py && uv run mypy`
Expected: tests PASS; ruff clean; mypy `Success`.

- [ ] **Step 7: Commit**

```bash
git add src/ippon/scanner/pipeline.py src/ippon/worker/tasks/scan.py tests/unit/test_secret_pipeline.py
git commit -m "feat(scanner): drive secret-scan flags from scan policy

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Reporter ingest of secret findings

**Files:**
- Modify: `src/ippon/reporter/ingest.py`
- Modify: `src/ippon/reporter/__main__.py`
- Modify: `src/ippon/schemas/scan.py` (`CallbackPayload`)
- Create: `tests/fixtures/betterleaks-report.json`
- Test: `tests/unit/test_secret_ingest.py`

**Interfaces:**
- Consumes: betterleaks JSON report (gitleaks schema), the `secret_findings` table + `scan_metrics` columns (Task 1).
- Produces:
  - `ingest.parse_validation(entry: dict) -> tuple[bool, str]`
  - `ingest.secret_finding_rows(secrets: list[dict], ctx: IngestContext, head_sha: str) -> tuple[list[dict], int]`
  - `IngestResult.secret_finding_count: int`, `IngestResult.verified_secret_count: int`
  - `ingest()` gains a keyword-only `secrets_path: Path | None = None`.
  - `CallbackPayload.secret_finding_count: int = 0`, `CallbackPayload.verified_secret_count: int = 0`.

- [ ] **Step 1: Create the fixture**

Create `tests/fixtures/betterleaks-report.json` (the HEAD commit is `2222...2222`; finding #1 is from an older commit, so historical):

```json
[
  {
    "Description": "AWS Access Key",
    "StartLine": 3,
    "EndLine": 3,
    "StartColumn": 1,
    "EndColumn": 40,
    "Match": "aws_access_key_id=REDACTED",
    "Secret": "REDACTED",
    "File": "config/old.env",
    "SymlinkFile": "",
    "Commit": "1111111111111111111111111111111111111111",
    "Entropy": 3.5,
    "Author": "Old Dev",
    "Email": "old@example.com",
    "Date": "2024-01-02T03:04:05Z",
    "Message": "add config",
    "Tags": [],
    "RuleID": "aws-access-token",
    "Fingerprint": "1111111111111111111111111111111111111111:config/old.env:aws-access-token:3"
  },
  {
    "Description": "Generic API Key",
    "StartLine": 10,
    "EndLine": 10,
    "StartColumn": 5,
    "EndColumn": 48,
    "Match": "api_key = REDACTED",
    "Secret": "REDACTED",
    "File": "src/app.py",
    "SymlinkFile": "",
    "Commit": "2222222222222222222222222222222222222222",
    "Entropy": 4.2,
    "Author": "Cur Dev",
    "Email": "cur@example.com",
    "Date": "2024-06-01T00:00:00Z",
    "Message": "wip",
    "Tags": ["key", "generic"],
    "RuleID": "generic-api-key",
    "Fingerprint": "2222222222222222222222222222222222222222:src/app.py:generic-api-key:10"
  }
]
```

- [ ] **Step 2: Write the failing test**

Create `tests/unit/test_secret_ingest.py`:

```python
"""Parsing betterleaks JSON into secret_findings rows."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from ippon.reporter.ingest import IngestContext, parse_validation, secret_finding_rows

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "betterleaks-report.json"
HEAD = "2222222222222222222222222222222222222222"


def _ctx() -> IngestContext:
    return IngestContext(
        scan_id=uuid4(),
        org_id=uuid4(),
        repo_id=uuid4(),
        commit_sha=HEAD,
        scanned_at=datetime.now(UTC),
        bucket="b",
        object_key="k",
    )


def test_parse_validation_defaults_to_unverified() -> None:
    assert parse_validation({}) == (False, "unverified")


def test_parse_validation_reads_live_marker() -> None:
    assert parse_validation({"Validation": "valid"}) == (True, "verified")
    assert parse_validation({"Validation": "invalid"}) == (False, "unknown")


def test_secret_rows_map_fields_and_history() -> None:
    secrets = json.loads(FIXTURE.read_text(encoding="utf-8"))
    rows, verified_count = secret_finding_rows(secrets, _ctx(), HEAD)

    assert len(rows) == 2
    assert verified_count == 0

    historical = next(r for r in rows if r["rule_id"] == "aws-access-token")
    current = next(r for r in rows if r["rule_id"] == "generic-api-key")

    assert historical["is_historical"] is True
    assert current["is_historical"] is False
    assert current["file"] == "src/app.py"
    assert current["start_line"] == 10
    assert current["tags"] == ["key", "generic"]
    assert current["validation_status"] == "unverified"
    assert current["verified"] is False
    assert historical["fingerprint"].endswith(":aws-access-token:3")


def test_secret_rows_store_only_redacted_match() -> None:
    secrets = json.loads(FIXTURE.read_text(encoding="utf-8"))
    rows, _ = secret_finding_rows(secrets, _ctx(), HEAD)
    for r in rows:
        # Security invariant: stored value is redacted; no key holds raw.
        assert "REDACTED" in r["match"]
        assert "Secret" not in r
        assert set(r.keys()) == {
            "scan_id", "org_id", "repo_id", "commit_sha", "rule_id", "description",
            "file", "start_line", "end_line", "match", "fingerprint", "author",
            "email", "committed_at", "tags", "verified", "validation_status",
            "is_historical", "scanned_at",
        }
```

- [ ] **Step 3: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_secret_ingest.py -v`
Expected: FAIL — `ImportError: cannot import name 'parse_validation'`.

- [ ] **Step 4: Implement the parser in ingest.py**

In `src/ippon/reporter/ingest.py`, add these functions (place them after `_finding_rows`, before `ingest`):

```python
def parse_validation(entry: dict[str, Any]) -> tuple[bool, str]:
    """Return ``(verified, validation_status)`` from a betterleaks entry.

    Detect-only is the default. The validation result field is
    version-dependent (see the spec's "items to confirm") — confirm the key
    against the pinned betterleaks version. We read ``Validation`` and map
    its value; absence means verification did not run.
    """
    raw = entry.get("Validation")
    if raw is None:
        return False, "unverified"
    val = str(raw).strip().lower()
    if val in {"valid", "active", "verified"}:
        return True, "verified"
    if val in {"invalid", "inactive"}:
        return False, "unknown"
    if val == "error":
        return False, "error"
    return False, "unverified"


def _parse_git_date(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def secret_finding_rows(
    secrets: list[dict[str, Any]], ctx: IngestContext, head_sha: str
) -> tuple[list[dict[str, Any]], int]:
    """Map betterleaks JSON entries to ``secret_findings`` rows.

    Returns ``(rows, verified_count)``. Only the redacted ``Match`` is kept —
    never the raw secret value.
    """
    rows: list[dict[str, Any]] = []
    verified_count = 0
    for entry in secrets:
        verified, status = parse_validation(entry)
        if verified:
            verified_count += 1
        commit = str(entry.get("Commit") or "")
        rows.append(
            {
                "scan_id": ctx.scan_id,
                "org_id": ctx.org_id,
                "repo_id": ctx.repo_id,
                "commit_sha": commit,
                "rule_id": str(entry.get("RuleID") or ""),
                "description": str(entry.get("Description") or ""),
                "file": str(entry.get("File") or ""),
                "start_line": int(entry.get("StartLine") or 0),
                "end_line": int(entry.get("EndLine") or 0),
                "match": str(entry.get("Match") or ""),
                "fingerprint": str(entry.get("Fingerprint") or ""),
                "author": str(entry.get("Author") or ""),
                "email": str(entry.get("Email") or ""),
                "committed_at": _parse_git_date(entry.get("Date")),
                "tags": [str(t) for t in (entry.get("Tags") or [])],
                "verified": verified,
                "validation_status": status,
                "is_historical": bool(commit and head_sha and commit != head_sha),
                "scanned_at": ctx.scanned_at,
            }
        )
    return rows, verified_count
```

- [ ] **Step 5: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_secret_ingest.py -v`
Expected: PASS (4 passed).

- [ ] **Step 6: Wire counts into IngestResult, ingest(), scan_metrics**

In `src/ippon/reporter/ingest.py`:

(a) Add two fields to `IngestResult` (after `severity_counts`):

```python
    secret_finding_count: int
    verified_secret_count: int
```

(b) Change the `ingest()` signature to add a keyword-only `secrets_path`:

```python
def ingest(
    *,
    sbom_path: Path,
    findings_path: Path,
    ctx: IngestContext,
    clickhouse_url: str,
    s3_endpoint_url: str,
    s3_access_key: str,
    s3_secret_key: str,
    scan_started_at: datetime,
    secrets_path: Path | None = None,
) -> IngestResult:
```

(c) Inside `ingest()`, after the existing `findings` insert block (after the `client.insert("findings", ...)` guard) and before the `scan_metrics` insert, add:

```python
        # Secret findings (optional stage). Missing/empty file → zero rows.
        secrets: list[dict[str, Any]] = []
        if secrets_path is not None and secrets_path.exists():
            raw_secrets = secrets_path.read_bytes()
            if raw_secrets.strip():
                secrets = json.loads(raw_secrets.decode("utf-8"))
        secret_rows, verified_secret_count = secret_finding_rows(secrets, ctx, ctx.commit_sha)
        if secret_rows:
            client.insert(
                "secret_findings",
                [list(r.values()) for r in secret_rows],
                column_names=list(secret_rows[0].keys()),
            )
        secret_finding_count = len(secret_rows)
```

(d) In the `scan_metrics` insert, add the two values at the end of the values list (after `ctx.scanned_at,`) and the two names at the end of `column_names` (after `"scanned_at",`):

```python
                    secret_finding_count,
                    verified_secret_count,
```
```python
                "secret_finding_count",
                "verified_secret_count",
```

(e) In the final `return IngestResult(...)`, add:

```python
        secret_finding_count=secret_finding_count,
        verified_secret_count=verified_secret_count,
```

- [ ] **Step 7: Wire the reporter entry point + callback schema**

In `src/ippon/schemas/scan.py`, add to `CallbackPayload` (after `finding_count: int = 0`):

```python
    secret_finding_count: int = 0
    verified_secret_count: int = 0
```

In `src/ippon/reporter/__main__.py`:

(a) After the `findings_path = ...` line (~line 49), add:

```python
    secrets_path = Path(os.environ.get("IPPON_SECRETS_PATH", "/artifacts/secrets.json"))
```

(b) In the `ingest(...)` call (happy path), add the new argument:

```python
            secrets_path=secrets_path,
```

(c) In the happy-path `payload = {...}` dict, after `"finding_count": ...`, add:

```python
        "secret_finding_count": ingest_result.secret_finding_count if ingest_result else 0,
        "verified_secret_count": ingest_result.verified_secret_count if ingest_result else 0,
```

- [ ] **Step 8: Run full suite + lint + types**

Run: `uv run pytest tests/unit/test_secret_ingest.py -v && uv run ruff check src/ippon/reporter src/ippon/schemas/scan.py && uv run mypy`
Expected: tests PASS; ruff clean; mypy `Success`.

- [ ] **Step 9: Commit**

```bash
git add src/ippon/reporter/ingest.py src/ippon/reporter/__main__.py src/ippon/schemas/scan.py tests/fixtures/betterleaks-report.json tests/unit/test_secret_ingest.py
git commit -m "feat(reporter): ingest redacted secret findings into ClickHouse

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Docker runner secret-scan stage + clone depth

**Files:**
- Modify: `src/ippon/scanner/runner/docker.py`
- Test: `tests/unit/test_betterleaks_args.py`

**Interfaces:**
- Consumes: `ScanJobSpec` secret fields (Task 2).
- Produces: pure helpers `_clone_entrypoint_cmd(depth: int) -> str`, `_clone_depth(spec) -> int`, `_betterleaks_cmd(spec) -> list[str]`, `_secret_scan_network(spec) -> str`; and the secret-scan step in `submit`.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_betterleaks_args.py`:

```python
"""Pure-helper coverage for the Docker runner's secret-scan stage."""

from __future__ import annotations

from uuid import uuid4

from ippon.scanner.runner.base import ScanJobSpec
from ippon.scanner.runner.docker import (
    _betterleaks_cmd,
    _clone_depth,
    _clone_entrypoint_cmd,
    _secret_scan_network,
)


def _spec(**overrides: object) -> ScanJobSpec:
    base: dict[str, object] = dict(
        scan_id=uuid4(),
        org_id=uuid4(),
        repo_id=uuid4(),
        repo_url="https://github.com/anchore/syft",
        ref="HEAD",
        clone_image="alpine/git:latest",
        syft_image="anchore/syft:latest",
        grype_image="anchore/grype:latest",
        reporter_image="ippon/backend:dev",
        grype_db_volume="ippon_grype_db",
        network="ippon_default",
        callback_url="http://api:8000/internal/scans/x/callback",
        callback_secret="s3cret",
        secret_scan_image="ghcr.io/betterleaks/betterleaks:v1.6.0",
    )
    base.update(overrides)
    return ScanJobSpec(**base)  # type: ignore[arg-type]


def test_betterleaks_cmd_redacts_and_never_fails_on_leaks() -> None:
    cmd = _betterleaks_cmd(_spec(secret_history_depth=128))
    assert cmd[0] == "git"
    assert "--redact" in cmd
    assert cmd[cmd.index("--exit-code") + 1] == "0"
    assert "--log-opts=-n 128" in cmd
    assert "/artifacts/secrets.json" in cmd


def test_clone_depth_shallow_when_secrets_disabled() -> None:
    assert _clone_depth(_spec(secret_scan_enabled=False, secret_history_depth=256)) == 1


def test_clone_depth_uses_history_when_enabled() -> None:
    assert _clone_depth(_spec(secret_scan_enabled=True, secret_history_depth=256)) == 256


def test_secret_scan_network_none_by_default() -> None:
    assert _secret_scan_network(_spec(verify_secrets=False)) == "none"


def test_secret_scan_network_bridge_when_verifying() -> None:
    assert _secret_scan_network(_spec(verify_secrets=True)) == "bridge"


def test_clone_entrypoint_uses_depth() -> None:
    assert "--depth=200" in _clone_entrypoint_cmd(200)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_betterleaks_args.py -v`
Expected: FAIL — `ImportError` on `_betterleaks_cmd`.

- [ ] **Step 3: Add the helpers + convert the clone command**

In `src/ippon/scanner/runner/docker.py`, replace the module-level `_CLONE_ENTRYPOINT_CMD = (...)` constant with a function, and add the three helpers below it:

```python
def _clone_entrypoint_cmd(depth: int) -> str:
    return (
        "set -e; "
        'if [ -n "$IPPON_REF" ] && [ "$IPPON_REF" != "HEAD" ]; then '
        f'  git clone --depth={depth} --branch "$IPPON_REF" "$IPPON_REPO_URL" /workspace; '
        "else "
        f'  git clone --depth={depth} "$IPPON_REPO_URL" /workspace; '
        "fi; "
        "git -C /workspace rev-parse HEAD > /artifacts/commit-sha.txt; "
        "echo cloned ${IPPON_REPO_URL} ref=${IPPON_REF:-default} sha=$(cat /artifacts/commit-sha.txt)"
    )


def _clone_depth(spec: ScanJobSpec) -> int:
    """Deep enough for secret history when enabled; shallow otherwise."""
    return spec.secret_history_depth if spec.secret_scan_enabled else 1


def _betterleaks_cmd(spec: ScanJobSpec) -> list[str]:
    """betterleaks args. ``--exit-code 0`` so 'leaks found' is a success;
    ``--redact`` so raw secrets never leave the container."""
    return [
        "git",
        "/workspace",
        "--report-format",
        "json",
        "--report-path",
        "/artifacts/secrets.json",
        "--redact",
        "--exit-code",
        "0",
        f"--log-opts=-n {spec.secret_history_depth}",
    ]


def _secret_scan_network(spec: ScanJobSpec) -> str:
    """Isolated by default; egress-capable 'bridge' only when verifying."""
    return "bridge" if spec.verify_secrets else "none"
```

- [ ] **Step 4: Use the helpers in `submit`**

In `DockerJobRunner.submit`:

(a) In the image-pull block, after `await self._ensure_image(docker, spec.grype_image)` add:

```python
            if spec.secret_scan_enabled:
                await self._ensure_image(docker, spec.secret_scan_image)
```

(b) In the clone step, change the `cmd` argument from `cmd=["sh", "-c", _CLONE_ENTRYPOINT_CMD]` to:

```python
                    cmd=["sh", "-c", _clone_entrypoint_cmd(_clone_depth(spec))],
```

(c) After the Grype step's `if step.exit_code != 0: failed_step, failed_reason = "grype", step.logs_tail` block, and before the `# 4. Reporter` comment, insert the secret-scan step:

```python
                # 3b. Secret scan (betterleaks). "Leaks found" exits 0; any
                # non-zero is a real error. Mounts the repo read-only.
                if failed_step is None and spec.secret_scan_enabled:
                    step = await self._run_step(
                        docker,
                        name="secret-scan",
                        image=spec.secret_scan_image,
                        cmd=_betterleaks_cmd(spec),
                        env={},
                        volumes={ws_volume: ("/workspace", "ro"), ar_volume: "/artifacts"},
                        network_mode=_secret_scan_network(spec),
                        labels={**labels, _LABEL_STEP: "secret-scan"},
                        name_suffix=f"secret-scan-{scan_id_short}",
                        mem_limit=spec.mem_limit,
                        cpu_count=spec.cpu_count,
                        deadline_seconds=spec.active_deadline_seconds,
                    )
                    if step.exit_code != 0:
                        failed_step, failed_reason = "secret-scan", step.logs_tail
```

- [ ] **Step 5: Run test + lint + types**

Run: `uv run pytest tests/unit/test_betterleaks_args.py tests/unit/test_docker_runner.py -v && uv run ruff check src/ippon/scanner/runner/docker.py && uv run mypy`
Expected: tests PASS; ruff clean; mypy `Success`.

- [ ] **Step 6: Commit**

```bash
git add src/ippon/scanner/runner/docker.py tests/unit/test_betterleaks_args.py
git commit -m "feat(scanner): add betterleaks secret-scan step to the Docker runner

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: K8s template secret-scan init container + clone depth

**Files:**
- Modify: `manifests/jobs/scan-job.yaml.j2`
- Modify: `src/ippon/scanner/runner/k8s.py` (`_render_job_manifest`)
- Test: `tests/unit/test_k8s_template.py`

**Interfaces:**
- Consumes: `ScanJobSpec` secret fields (Task 2).
- Produces: a rendered Job whose init containers are `[clone, syft, grype, secret-scan]` when secret scanning is enabled, `[clone, syft, grype]` when disabled; clone uses `--depth={{ clone_depth }}`.

> K8s pods share one network namespace and per-container egress is a NetworkPolicy concern (out of scope here, per the template's own comment). The init container always passes `--exit-code 0` and the capped `--log-opts`; verification egress in k8s is governed by cluster NetworkPolicy.

- [ ] **Step 1: Update the failing tests**

In `tests/unit/test_k8s_template.py`:

(a) Replace the helper `_spec(scan_id, org_id, repo_id)` signature with one that accepts a secret toggle — change its `def` line to:

```python
def _spec(
    scan_id: UUID, org_id: UUID, repo_id: UUID, *, secret_scan_enabled: bool = True
) -> ScanJobSpec:
```

and add `secret_scan_enabled=secret_scan_enabled,` to the `ScanJobSpec(...)` it returns.

(b) Replace the existing `test_init_containers_are_clone_syft_grype_in_order` with:

```python
def test_init_containers_include_secret_scan_in_order() -> None:
    spec = _spec(uuid4(), uuid4(), uuid4())
    job, _, _ = _render_job_manifest(
        spec,
        namespace="ippon-scans",
        service_account="ippon-scanner",
        grype_db_pvc="grype-db-shared",
    )
    init_names = [c["name"] for c in job["spec"]["template"]["spec"]["initContainers"]]
    assert init_names == ["clone", "syft", "grype", "secret-scan"]


def test_secret_scan_omitted_when_disabled() -> None:
    spec = _spec(uuid4(), uuid4(), uuid4(), secret_scan_enabled=False)
    job, _, _ = _render_job_manifest(
        spec,
        namespace="ippon-scans",
        service_account="ippon-scanner",
        grype_db_pvc="grype-db-shared",
    )
    init_names = [c["name"] for c in job["spec"]["template"]["spec"]["initContainers"]]
    assert init_names == ["clone", "syft", "grype"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/test_k8s_template.py -v`
Expected: FAIL — `_render_job_manifest` raises `jinja2.UndefinedError` for the new template variables (StrictUndefined), or the init list lacks `secret-scan`.

- [ ] **Step 3: Edit the Jinja template**

In `manifests/jobs/scan-job.yaml.j2`:

(a) In the clone init container's `args`, change both `git clone --depth=1` occurrences to `git clone --depth={{ clone_depth }}`:

```yaml
              if [ -n "$IPPON_REF" ] && [ "$IPPON_REF" != "HEAD" ]; then
                git clone --depth={{ clone_depth }} --branch "$IPPON_REF" "$IPPON_REPO_URL" /workspace
              else
                git clone --depth={{ clone_depth }} "$IPPON_REPO_URL" /workspace
              fi
```

(b) Immediately after the `grype` init container block (after its `volumeMounts`, before `      containers:`), add:

```yaml
{% if secret_scan_enabled %}
        - name: secret-scan
          image: {{ secret_scan_image }}
          imagePullPolicy: IfNotPresent
          # "leaks found" exits 0 (--exit-code 0); --redact keeps raw
          # secrets out of the report. Repo mounted read-only.
          args:
            - "git"
            - "/workspace"
            - "--report-format"
            - "json"
            - "--report-path"
            - "/artifacts/secrets.json"
            - "--redact"
            - "--exit-code"
            - "0"
            - "--log-opts=-n {{ secret_history_depth }}"
          resources:
            requests: { memory: "256Mi", cpu: "100m" }
            limits:   { memory: "{{ mem_limit }}", cpu: "{{ cpu_limit }}" }
          volumeMounts:
            - { name: workspace, mountPath: /workspace, readOnly: true }
            - { name: artifacts, mountPath: /artifacts }
{% endif %}
```

- [ ] **Step 4: Pass the new variables from the renderer**

In `src/ippon/scanner/runner/k8s.py`, inside `_render_job_manifest`'s `.render(...)` call, add (after `cpu_limit=str(spec.cpu_count),`):

```python
        secret_scan_image=spec.secret_scan_image,
        secret_scan_enabled=spec.secret_scan_enabled,
        secret_history_depth=spec.secret_history_depth,
        clone_depth=(spec.secret_history_depth if spec.secret_scan_enabled else 1),
```

- [ ] **Step 5: Run the full template test file**

Run: `uv run pytest tests/unit/test_k8s_template.py -v`
Expected: PASS — including `test_all_resource_quantities_are_valid_k8s` (the new container's `256Mi`/`100m`/`2Gi`/`1.0` are valid quantities) and the two new ordering tests.

- [ ] **Step 6: Lint + types**

Run: `uv run ruff check src/ippon/scanner/runner/k8s.py tests/unit/test_k8s_template.py && uv run mypy`
Expected: ruff clean; mypy `Success`.

- [ ] **Step 7: Commit**

```bash
git add manifests/jobs/scan-job.yaml.j2 src/ippon/scanner/runner/k8s.py tests/unit/test_k8s_template.py
git commit -m "feat(scanner): add secret-scan init container to the K8s job template

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 8: Inline runner clone depth

**Files:**
- Modify: `src/ippon/scanner/runner/inline.py`
- Test: `tests/unit/test_inline_clone_cmd.py`

**Interfaces:**
- Consumes: `ScanJobSpec` secret fields (Task 2).
- Produces: `InlineJobRunner._clone_cmd(spec, workspace) -> list[str]`, used by `_clone`.

> The inline runner is a test-only fallback that does not run the reporter, so it ingests nothing; this task only makes its clone depth consistent so history is present if someone runs it directly.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_inline_clone_cmd.py`:

```python
"""Inline runner clone command honours the configured history depth."""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from ippon.scanner.runner.base import ScanJobSpec
from ippon.scanner.runner.inline import InlineJobRunner


def _spec(**overrides: object) -> ScanJobSpec:
    base: dict[str, object] = dict(
        scan_id=uuid4(),
        org_id=uuid4(),
        repo_id=uuid4(),
        repo_url="https://github.com/anchore/syft",
        ref="HEAD",
        clone_image="alpine/git:latest",
        syft_image="anchore/syft:latest",
        grype_image="anchore/grype:latest",
        reporter_image="ippon/backend:dev",
        grype_db_volume="ippon_grype_db",
        network="ippon_default",
        callback_url="http://api:8000/internal/scans/x/callback",
        callback_secret="s3cret",
        secret_scan_image="ghcr.io/betterleaks/betterleaks:v1.6.0",
    )
    base.update(overrides)
    return ScanJobSpec(**base)  # type: ignore[arg-type]


def test_clone_cmd_uses_history_depth_when_enabled() -> None:
    cmd = InlineJobRunner._clone_cmd(_spec(secret_history_depth=64), Path("/tmp/ws"))
    assert "--depth=64" in cmd


def test_clone_cmd_shallow_when_secrets_disabled() -> None:
    cmd = InlineJobRunner._clone_cmd(_spec(secret_scan_enabled=False), Path("/tmp/ws"))
    assert "--depth=1" in cmd


def test_clone_cmd_adds_branch_for_non_head_ref() -> None:
    cmd = InlineJobRunner._clone_cmd(_spec(ref="main"), Path("/tmp/ws"))
    assert "--branch" in cmd
    assert "main" in cmd
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_inline_clone_cmd.py -v`
Expected: FAIL — `AttributeError: ... has no attribute '_clone_cmd'`.

- [ ] **Step 3: Extract `_clone_cmd` and use it in `_clone`**

In `src/ippon/scanner/runner/inline.py`, add a static method and rewrite the start of `_clone`:

```python
    @staticmethod
    def _clone_cmd(spec: ScanJobSpec, workspace: Path) -> list[str]:
        depth = spec.secret_history_depth if spec.secret_scan_enabled else 1
        cmd = ["git", "clone", f"--depth={depth}"]
        if spec.ref and spec.ref != "HEAD":
            cmd += ["--branch", spec.ref]
        cmd += [spec.repo_url, str(workspace)]
        return cmd

    @staticmethod
    def _clone(spec: ScanJobSpec, workspace: Path, artifacts: Path) -> None:
        LOG.info("[inline] cloning %s ref=%s", spec.repo_url, spec.ref)
        subprocess.run(InlineJobRunner._clone_cmd(spec, workspace), check=True, capture_output=True)
        sha = subprocess.run(
            ["git", "-C", str(workspace), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        (artifacts / "commit-sha.txt").write_text(sha + "\n", encoding="utf-8")
```

(Delete the old `cmd = ["git", "clone", "--depth=1"] ... subprocess.run(cmd, ...)` lines that this replaces.)

- [ ] **Step 4: Run test + lint + types**

Run: `uv run pytest tests/unit/test_inline_clone_cmd.py -v && uv run ruff check src/ippon/scanner/runner/inline.py && uv run mypy`
Expected: tests PASS; ruff clean; mypy `Success`.

- [ ] **Step 5: Commit**

```bash
git add src/ippon/scanner/runner/inline.py tests/unit/test_inline_clone_cmd.py
git commit -m "feat(scanner): honour history depth in the inline runner clone

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 9: Secrets API endpoint

**Files:**
- Create: `src/ippon/schemas/secret.py`
- Modify: `src/ippon/api/routes/scans.py`
- Test: `tests/unit/test_secrets_endpoint.py`

**Interfaces:**
- Consumes: the `secret_findings` table (Task 1), `CHDep`/`CurrentUser` deps, `get_ch_client`.
- Produces: `SecretFinding`, `SecretFindingPage` (`src/ippon/schemas/secret.py`); route `GET /scans/{scan_id}/secrets` returning `SecretFindingPage`. Consumed by Tasks 10–11.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_secrets_endpoint.py`:

```python
"""GET /scans/{id}/secrets with a stubbed ClickHouse client."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from ippon.api.deps import get_ch_client
from ippon.api.main import create_app
from ippon.config import Settings


class _FakeResult:
    def __init__(self, rows: list[list[Any]]) -> None:
        self.result_rows = rows


class _FakeCH:
    def __init__(self, row: list[Any]) -> None:
        self._row = row

    def query(self, sql: str, parameters: dict[str, Any] | None = None) -> _FakeResult:
        if "count()" in sql:
            return _FakeResult([[1]])
        return _FakeResult([self._row])


@pytest.fixture
def client() -> Iterator[TestClient]:
    app = create_app(Settings(ippon_dev_token="test-token"))
    scan_id = uuid4()
    row = [
        scan_id,                       # scan_id
        "aws-access-token",            # rule_id
        "AWS Access Key",              # description
        "config/old.env",             # file
        3,                             # start_line
        3,                             # end_line
        "aws_access_key_id=REDACTED",  # match
        "1111:config/old.env:aws-access-token:3",  # fingerprint
        "Old Dev",                     # author
        "old@example.com",             # email
        datetime(2024, 1, 2, tzinfo=UTC),  # committed_at
        ["k"],                         # tags
        False,                         # verified
        "unverified",                  # validation_status
        True,                          # is_historical
        datetime.now(UTC),             # scanned_at
    ]
    app.dependency_overrides[get_ch_client] = lambda: _FakeCH(row)
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_list_secrets_returns_redacted_rows(client: TestClient) -> None:
    r = client.get(
        f"/scans/{uuid4()}/secrets",
        headers={"Authorization": "Bearer test-token"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 1
    item = body["items"][0]
    assert item["rule_id"] == "aws-access-token"
    assert "REDACTED" in item["match"]
    assert item["is_historical"] is True
    assert item["verified"] is False


def test_list_secrets_requires_auth(client: TestClient) -> None:
    r = client.get(f"/scans/{uuid4()}/secrets")
    assert r.status_code == 401
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_secrets_endpoint.py -v`
Expected: FAIL — route returns 404 (not yet defined).

- [ ] **Step 3: Add the schema**

Create `src/ippon/schemas/secret.py`:

```python
"""Pydantic models for the secret-findings API."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class SecretFinding(BaseModel):
    """One row from ClickHouse ``secret_findings`` (redacted)."""

    scan_id: UUID
    rule_id: str
    description: str
    file: str
    start_line: int
    end_line: int
    match: str
    fingerprint: str
    author: str
    email: str
    committed_at: datetime | None
    tags: list[str]
    verified: bool
    validation_status: str
    is_historical: bool
    scanned_at: datetime


class SecretFindingPage(BaseModel):
    items: list[SecretFinding]
    total: int
    limit: int
    offset: int
```

- [ ] **Step 4: Add the route**

In `src/ippon/api/routes/scans.py`, add the import (next to the finding-schema import):

```python
from ippon.schemas.secret import SecretFinding, SecretFindingPage
```

At the end of the file, add:

```python
@router.get(
    "/{scan_id}/secrets",
    response_model=SecretFindingPage,
    summary="List secret findings for a scan, paginated.",
)
async def list_secrets(
    scan_id: UUID,
    _: CurrentUser,
    ch: CHDep,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    validation_status: Annotated[
        str | None,
        Query(description="Filter by validation status (verified/unverified/unknown/error)."),
    ] = None,
) -> SecretFindingPage:
    where = "scan_id = {scan_id:UUID}"
    params: dict[str, Any] = {"scan_id": str(scan_id), "limit": limit, "offset": offset}
    if validation_status:
        where += " AND validation_status = {validation_status:String}"
        params["validation_status"] = validation_status

    count_sql = f"SELECT count() FROM secret_findings WHERE {where}"
    rows_sql = f"""
        SELECT scan_id, rule_id, description, file, start_line, end_line,
               match, fingerprint, author, email, committed_at, tags,
               verified, validation_status, is_historical, scanned_at
        FROM secret_findings
        WHERE {where}
        ORDER BY verified DESC, is_historical ASC, rule_id ASC
        LIMIT {{limit:UInt32}} OFFSET {{offset:UInt32}}
    """

    total_row = await asyncio.to_thread(ch.query, count_sql, parameters=params)
    total = int(total_row.result_rows[0][0]) if total_row.result_rows else 0

    page = await asyncio.to_thread(ch.query, rows_sql, parameters=params)
    items: list[SecretFinding] = []
    for row in page.result_rows:
        items.append(
            SecretFinding(
                scan_id=row[0],
                rule_id=row[1],
                description=row[2],
                file=row[3],
                start_line=row[4],
                end_line=row[5],
                match=row[6],
                fingerprint=row[7],
                author=row[8],
                email=row[9],
                committed_at=row[10],
                tags=list(row[11]) if row[11] is not None else [],
                verified=bool(row[12]),
                validation_status=row[13],
                is_historical=bool(row[14]),
                scanned_at=row[15],
            )
        )

    return SecretFindingPage(items=items, total=total, limit=limit, offset=offset)
```

- [ ] **Step 5: Run test + lint + types**

Run: `uv run pytest tests/unit/test_secrets_endpoint.py tests/unit/test_api_smoke.py -v && uv run ruff check src/ippon/api/routes/scans.py src/ippon/schemas/secret.py && uv run mypy`
Expected: tests PASS; ruff clean; mypy `Success`.

- [ ] **Step 6: Commit**

```bash
git add src/ippon/schemas/secret.py src/ippon/api/routes/scans.py tests/unit/test_secrets_endpoint.py
git commit -m "feat(api): add GET /scans/{id}/secrets endpoint

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 10: Web API client — SecretFinding + listSecrets

**Files:**
- Modify: `web/src/api/client.ts`

**Interfaces:**
- Consumes: the `/scans/{id}/secrets` endpoint shape (Task 9).
- Produces: `SecretFinding`, `SecretFindingPage`, `ValidationStatus` types and `listSecrets(args)` function. Consumed by Task 11.

- [ ] **Step 1: Add the types + function**

In `web/src/api/client.ts`, after the `FindingPage` interface (~line 88), add:

```typescript
export type ValidationStatus = "verified" | "unverified" | "unknown" | "error";

export interface SecretFinding {
  scan_id: string;
  rule_id: string;
  description: string;
  file: string;
  start_line: number;
  end_line: number;
  match: string;
  fingerprint: string;
  author: string;
  email: string;
  committed_at: string | null;
  tags: string[];
  verified: boolean;
  validation_status: ValidationStatus;
  is_historical: boolean;
  scanned_at: string;
}

export interface SecretFindingPage {
  items: SecretFinding[];
  total: number;
  limit: number;
  offset: number;
}
```

After the `listFindings` function (end of file), add:

```typescript
export interface ListSecretsArgs {
  scanId: string;
  limit?: number;
  offset?: number;
  validationStatus?: ValidationStatus;
}

export function listSecrets(args: ListSecretsArgs): Promise<SecretFindingPage> {
  return fetcher<SecretFindingPage>({
    url: `/scans/${args.scanId}/secrets`,
    method: "GET",
    params: {
      limit: args.limit,
      offset: args.offset,
      validation_status: args.validationStatus,
    },
  });
}
```

- [ ] **Step 2: Typecheck**

Run: `pnpm --dir web lint`
Expected: PASS (no TypeScript errors).

- [ ] **Step 3: Commit**

```bash
git add web/src/api/client.ts
git commit -m "feat(web): add SecretFinding client types + listSecrets

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 11: Web UI — VerifiedBadge + Secrets table

**Files:**
- Modify: `web/src/components/ui/badge.tsx`
- Modify: `web/src/routes/scans/$id.tsx`

**Interfaces:**
- Consumes: `listSecrets`, `SecretFinding`, `ValidationStatus` (Task 10); the existing `Badge`, `Table`/`TBody`/`TD`/`TH`/`THead`/`TR`, `Button`, `formatDateTime` primitives.
- Produces: `VerifiedBadge` component; a Secrets section on the scan-detail page.

- [ ] **Step 1: Add `VerifiedBadge`**

In `web/src/components/ui/badge.tsx`, after `StatusBadge`, add:

```typescript
const VALIDATION_TONE = {
  verified: "critical", // live secret — highest concern (red)
  error: "medium", // verification errored (amber)
  unverified: "muted",
  unknown: "muted",
} as const;

export function VerifiedBadge({ status }: { status: string }) {
  const tone = VALIDATION_TONE[status as keyof typeof VALIDATION_TONE] ?? "muted";
  const label = status === "verified" ? "live" : status;
  return <Badge tone={tone}>{label}</Badge>;
}
```

- [ ] **Step 2: Add the Secrets table to the scan page**

In `web/src/routes/scans/$id.tsx`:

(a) Extend the API import to add the secrets symbols:

```typescript
import {
  getScan,
  listFindings,
  listSecrets,
  type Finding,
  type SecretFinding,
  type Severity,
} from "@/api/client";
```

(b) Extend the badge import:

```typescript
import { SeverityBadge, StatusBadge, VerifiedBadge } from "@/components/ui/badge";
```

(c) After the existing `columns` definition for findings, add a secrets column helper + columns:

```typescript
const secretColumnHelper = createColumnHelper<SecretFinding>();

const secretColumns = [
  secretColumnHelper.accessor("validation_status", {
    header: "Status",
    cell: (info) => <VerifiedBadge status={info.getValue()} />,
  }),
  secretColumnHelper.accessor("rule_id", {
    header: "Rule",
    cell: (info) => (
      <span className="font-mono text-xs text-zinc-900">{info.getValue()}</span>
    ),
  }),
  secretColumnHelper.accessor("match", {
    header: "Match",
    cell: (info) => (
      <span className="font-mono text-xs text-zinc-600">{info.getValue()}</span>
    ),
  }),
  secretColumnHelper.display({
    id: "location",
    header: "Location",
    cell: ({ row }) => (
      <span className="font-mono text-xs text-zinc-600">
        {row.original.file}:{row.original.start_line}
      </span>
    ),
  }),
  secretColumnHelper.accessor("commit_sha" as never, {
    id: "commit",
    header: "Commit",
    cell: ({ row }) => (
      <span className="text-zinc-500">
        {row.original.is_historical ? (
          <Badge tone="muted">historical</Badge>
        ) : (
          <span className="text-xs">HEAD</span>
        )}
      </span>
    ),
  }),
  secretColumnHelper.accessor("committed_at", {
    header: "Committed",
    cell: (info) => <span className="text-zinc-500">{formatDateTime(info.getValue())}</span>,
  }),
];
```

Add `Badge` to the badge import line so the "historical" chip works:

```typescript
import { Badge, SeverityBadge, StatusBadge, VerifiedBadge } from "@/components/ui/badge";
```

(d) Inside `ScanPage`, after the `findingsQuery` definition, add the secrets query + table:

```typescript
  const secretsQuery = useQuery({
    queryKey: ["secrets", id],
    queryFn: () => listSecrets({ scanId: id, limit: 200 }),
    enabled: scanQuery.data?.status === "succeeded",
  });

  const secretsTable = useReactTable({
    data: secretsQuery.data?.items ?? [],
    columns: secretColumns,
    getCoreRowModel: getCoreRowModel(),
  });
```

(e) Just before the closing `</section>` of the returned JSX (after the findings pagination `<div>`), add the Secrets section:

```tsx
      <div className="space-y-3">
        <h2 className="font-mono text-sm uppercase tracking-wide text-zinc-500">
          Secrets {secretsQuery.data ? `(${secretsQuery.data.total})` : ""}
        </h2>
        <Table>
          <THead>
            {secretsTable.getHeaderGroups().map((hg) => (
              <TR key={hg.id}>
                {hg.headers.map((h) => (
                  <TH key={h.id}>{flexRender(h.column.columnDef.header, h.getContext())}</TH>
                ))}
              </TR>
            ))}
          </THead>
          <TBody>
            {secretsQuery.isLoading && (
              <TR>
                <TD colSpan={secretColumns.length} className="text-center text-zinc-400 py-8">
                  loading…
                </TD>
              </TR>
            )}
            {!secretsQuery.isLoading && secretsTable.getRowModel().rows.length === 0 && (
              <TR>
                <TD colSpan={secretColumns.length} className="text-center text-zinc-400 py-8">
                  No secrets detected.
                </TD>
              </TR>
            )}
            {secretsTable.getRowModel().rows.map((row) => (
              <TR key={row.id}>
                {row.getVisibleCells().map((cell) => (
                  <TD key={cell.id}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</TD>
                ))}
              </TR>
            ))}
          </TBody>
        </Table>
      </div>
```

- [ ] **Step 3: Typecheck the web app**

Run: `pnpm --dir web lint`
Expected: PASS (no TypeScript errors).

> If TanStack Table's typed `accessor` rejects the `"commit_sha" as never` column, replace that column with a `secretColumnHelper.display({ id: "commit", header: "Commit", cell: ({ row }) => ... })` block (same cell body) — `display` columns need no data key.

- [ ] **Step 4: Build to confirm it bundles**

Run: `pnpm --dir web build`
Expected: build succeeds (tsc + vite).

- [ ] **Step 5: Commit**

```bash
git add web/src/components/ui/badge.tsx web/src/routes/scans/$id.tsx
git commit -m "feat(web): show secret findings on the scan page

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Final verification

After all tasks, run the full gate:

- [ ] `uv run ruff check . && uv run ruff format --check .` — clean
- [ ] `uv run mypy` — `Success`
- [ ] `uv run pytest` — all green (unit; integration + k8s remain opt-in)
- [ ] `pnpm --dir web lint && pnpm --dir web build` — clean
- [ ] Optional end-to-end (needs Docker): `just up && just migrate && just scan https://github.com/anchore/syft`, then open the scan in the UI and confirm the Secrets section renders.

## Self-review (performed against the spec)

**Spec coverage:**
- Pipeline stage between Grype and reporter → Tasks 6 (Docker), 7 (K8s), 8 (inline clone depth). ✓
- betterleaks engine, `--redact`, `--exit-code 0`, `--log-opts` capped history → Tasks 6, 7. ✓
- Detect-only default, verify opt-in per policy → Tasks 3, 4 (policy + flags), 6 (`_secret_scan_network`). ✓
- Raw secret never persisted → Task 5 (`secret_finding_rows` keeps only `Match`; test asserts it) + `--redact` at the tool. ✓
- `secret_findings` table + `scan_metrics` counts → Task 1; ingest → Task 5. ✓
- API endpoint → Task 9; counts on `CallbackPayload` → Task 5. ✓
- Web UI (Secrets view, verified badge, historical marker) → Tasks 10, 11. ✓
- ML deferred → no task (correct; out of scope). ✓

**Deliberate refinement vs spec:** the spec mentioned adding the two counts to `ScanResponse`. The codebase derives CVE finding totals from the list endpoint's `total` (the callback handler ignores count fields and `scan_jobs` has no count columns), so to stay consistent and avoid an unnecessary Postgres migration, the Secrets table shows its count via the list `total` and the counts live on `CallbackPayload` + `scan_metrics` (telemetry) only. No `ScanResponse`/`scan_jobs` change.

**Placeholder scan:** no TBD/TODO; every code step shows full code. The one version-dependent unknown (betterleaks validation field name) is implemented defensively in `parse_validation` and flagged in-code, matching the spec's "items to confirm."

**Type consistency:** `secret_finding_rows`/`parse_validation` names match between `ingest.py` and `test_secret_ingest.py`; `ScanJobSpec` field names (`secret_scan_image`, `secret_scan_enabled`, `verify_secrets`, `secret_history_depth`) are identical across config, pipeline, both runners, and the k8s template render; the `secret_findings` column order in the migration matches the SELECT in Task 9 and the row dict in Task 5.
