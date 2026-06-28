# Secret Detection — Design

- **Date:** 2026-06-28
- **Status:** Approved (design); pending spec review
- **Author:** ippon contributors (brainstormed with Claude)
- **Scope:** one implementation plan (backend pipeline + storage + API + Web UI)

## Summary

Add **secret detection** as a new stage in the scan pipeline. Each scan grows
from `clone → Syft → Grype → reporter` to
`clone → Syft → Grype → **secret-scan** → reporter`. The new stage runs
[**betterleaks**](https://github.com/betterleaks/betterleaks) (the MIT-licensed
gitleaks successor, by gitleaks' original author) against the cloned repo,
scanning a **capped slice of git history**, optionally **verifying** whether a
detected credential is live, and writing a **redacted** JSON report the reporter
ingests into a new ClickHouse table. Findings surface in the API and the Web UI
alongside CVE findings.

This is **Phase 1**. Machine learning is explicitly deferred to a data-justified
Phase 2 (see [Phase 2](#phase-2--ml-deferred)).

## Background

ippon scans a repo's **dependencies** for known CVEs (Syft SBOM → Grype). It
does nothing about **what is in the code itself**. Secrets committed to source —
API keys, tokens, private keys — are one of the highest-frequency, highest-impact
classes of repo security problem, and detecting them is the most natural security
capability to add next:

- It slots into the existing ephemeral, per-scan container chain with **one new
  stage** and **no new orchestration concept** — exactly how Syft and Grype work
  today (an upstream tool image reads the shared `/workspace` volume and writes a
  JSON artifact to `/artifacts` that the reporter ingests).
- Its findings sit naturally next to CVE findings in ClickHouse.
- The project already cares about secrets — it scans its *own* repo with
  GitGuardian (`.gitguardian.yml`). This feature gives ippon's users the same
  protection ippon already applies to itself.

## Goals

- Detect secrets across a **capped window of git history**, not just the working
  tree — secrets are frequently committed then "removed" in a later commit while
  remaining recoverable in history.
- **Optionally verify** that a detected secret is live, gated per scan policy.
- **Never become a place secrets leak to:** the raw secret value must never be
  persisted to ClickHouse, S3, the callback, or any log.
- Surface findings through the API and a Web UI view, mirroring the existing CVE
  findings experience.
- Keep the change to **one reviewable implementation plan**.

## Non-goals

- ML-based detection or false-positive reduction (Phase 2; see below).
- A separate, independently-scheduled secret-scan job type (rejected — see
  [Approaches](#approaches-considered)).
- Decrypting/revealing the full secret value in the UI (rejected — redacted +
  fingerprint only).
- Authoring custom betterleaks detection rules beyond what's needed to toggle
  verification; the bundled ruleset is the baseline.

## Locked decisions

| Decision | Choice | Rationale |
|---|---|---|
| Feature shape | New `secret-scan` pipeline stage | Mirrors Syft/Grype; zero new orchestration |
| Engine | **betterleaks** (`ghcr.io/betterleaks/betterleaks`) | MIT license, native redaction + fingerprint + verification, gitleaks-lineage history scanning |
| Scope | Capped git history (`--log-opts="-n <depth>"`) | Most value without unbounded clone/scan time |
| Verification | Detect-only default; opt-in per scan policy | Best precision when wanted; no surprise egress otherwise |
| Secret handling | Tool-level `--redact`; store native `Fingerprint` | Raw never leaves the betterleaks container; no custom image needed |
| UI | **In scope** for this spec | Backend + API + Web view ship together |
| ML | Deferred to Phase 2 | Justify with measured FP data before building |

### Why betterleaks over trufflehog

- **License:** MIT vs trufflehog's AGPL-3.0 — unambiguously clean for an
  Apache-2.0 project that ships scanner images.
- **`--redact`:** redaction happens *in the tool*, so the raw secret never lands
  in the `/artifacts` volume at all — no custom image, no reporter-side raw
  handling. Strongest data-handling posture, for free.
- **Native `Fingerprint`** (`commit:file:ruleID:startline`) satisfies the
  tracking/dedup requirement and supports a `.gitleaksignore`-style ignore model.
- **Native async verification** with in-memory caching (one network call per
  unique secret), enabled via a validation-enabled config + egress.
- **`--log-opts`** gives capped history directly (gitleaks-lineage, battle-tested).
- **BPE "token-efficiency" filtering** — a built-in statistical false-positive
  reducer that shrinks (does not eliminate) Phase 2's job.

**Accepted trade-off:** tool-level `--redact` means we cannot compute a
*value-level* hash, so we cannot dedup "the same secret value across different
files." We rely on the location-based `Fingerprint` (which changes if a secret
moves files). This is the standard gitleaks model and is sufficient for per-repo
tracking and ignore lists. We deliberately do **not** run a partial redact just to
hash the visible portion — that would weaken the no-raw posture for marginal gain.

## Approaches considered

- **A — New `secret-scan` stage in the chain (chosen).** An upstream tool image
  reads the shared volume and writes a JSON artifact the reporter ingests.
  Mirrors Syft/Grype; no new orchestration concept.
- **B — Fold betterleaks into the reporter or clone container (rejected).** Fewer
  containers, but couples two tools in one image and breaks one-stage-one-job.
- **C — A separate secret-scan job type / pipeline (rejected).** More flexible
  (independent cadence) but doubles orchestration and yields two jobs per push.
  Premature; revisit only if independent scheduling is ever required.

## Architecture

### Pipeline stage

A new stage runs between Grype and the reporter:

```
clone → syft → grype → secret-scan → reporter
```

- **Image:** `ghcr.io/betterleaks/betterleaks:<pinned-tag>` (tag pinned in
  `Settings`, like the Syft/Grype images — versions baked into the tag).
- **Inputs:** mounts the existing `/workspace` (the cloned git repo, with history)
  and `/artifacts` volumes. No new volume.
- **Output:** `/artifacts/secrets.json` (betterleaks JSON report).
- **Invocation:**
  ```
  betterleaks git /workspace \
    --report-format json --report-path /artifacts/secrets.json \
    --redact --exit-code 0 \
    --log-opts="-n {secret_history_depth}" \
    [--config /config/.betterleaks.toml]
  ```
- **Exit semantics:** betterleaks (gitleaks-lineage) returns exit 1 when leaks are
  found by default. We pass **`--exit-code 0`** so *"leaks found" is a success*.
  Any non-zero exit then signals a **genuine error** → `failed_step="secret-scan"`,
  and the reporter still runs via the existing `IPPON_FAILED=1` short-circuit path.
- **Network:**
  - Detect-only (default): `network_mode="none"` — same isolation as Syft/Grype.
  - Verify (policy opt-in): the stage joins an egress-capable network and uses a
    validation-enabled config so betterleaks can make the `validate` HTTP calls.

### Clone stage change

The clone stage today does `git clone --depth=1` (shallow). Secret history
scanning needs depth. Change it to honor a configurable depth:

- `git clone --depth={secret_history_depth}` (default cap **256**), still pinned to
  the requested ref. The clone already writes `/artifacts/commit-sha.txt` (HEAD);
  that file is reused to compute `is_historical` (a finding's commit ≠ HEAD).
- This is the **only** change to an existing stage. Syft/Grype continue to scan the
  checked-out tree at HEAD and are unaffected by the added depth.

### Runner integration

All three backends implement the same chain shape, so the stage is added to each:

- **DockerJobRunner** (`scanner/runner/docker.py`): insert a `_run_step(name="secret-scan", …)`
  between the Grype and reporter steps, following the existing short-circuit
  pattern (`if failed_step is None:`), with `network_mode` selected by the verify
  flag.
- **K8sJobRunner** (`scanner/runner/k8s.py`): add a `secret-scan` init-container to
  the Jinja Job manifest template, in chain order.
- **InlineJobRunner** (`scanner/runner/inline.py`): add the equivalent subprocess
  step for tests.

### ScanJobSpec / pipeline

`ScanJobSpec` (`scanner/runner/base.py`) gains:

- `secret_scan_image: str`
- `secret_scan_enabled: bool` (default `True`)
- `verify_secrets: bool` (default `False`)
- `secret_history_depth: int` (default `256`)

`build_scan_job_spec` (`scanner/pipeline.py`) populates these from `Settings` and
the repo's `scan_policy`. When `secret_scan_enabled` is false, the runner skips the
stage entirely (no container, no artifact) and the reporter records zero secrets.

## Data model

### ClickHouse — new `secret_findings` table

Mirrors the engine/partitioning of the existing `findings` table
(`migrations/clickhouse/0001_initial.sql`). Columns follow the betterleaks/gitleaks
JSON shape:

| Column | Type | Notes |
|---|---|---|
| `scan_id` | UUID | |
| `org_id` | UUID | |
| `repo_id` | UUID | |
| `commit_sha` | String | commit where the secret was found |
| `rule_id` | String | betterleaks `RuleID` (e.g. `aws-access-token`) |
| `description` | String | betterleaks `Description` |
| `file` | String | `File` |
| `start_line` | UInt32 | `StartLine` |
| `end_line` | UInt32 | `EndLine` |
| `match` | String | `Match`, **already redacted** by `--redact` |
| `fingerprint` | String | native `commit:file:ruleID:startline` |
| `author` | String | `Author` |
| `email` | String | `Email` |
| `committed_at` | DateTime | `Date` |
| `tags` | Array(String) | `Tags` |
| `verified` | Bool | true only when validation ran and returned live |
| `validation_status` | Enum | `verified` / `unverified` / `unknown` / `error` |
| `is_historical` | Bool | `commit_sha != HEAD` (from `commit-sha.txt`) |
| `scanned_at` | DateTime | |

A new migration file under `migrations/clickhouse/` creates the table; applied by
the existing `migrations/clickhouse/apply.py` path.

### ClickHouse — `scan_metrics`

Add `secret_finding_count` and `verified_secret_count` columns (alongside the
existing dependency/finding counts), populated by the reporter.

### Postgres — `scan_policy`

Add three columns via one Alembic migration:

- `secret_scan_enabled BOOLEAN NOT NULL DEFAULT true`
- `verify_secrets BOOLEAN NOT NULL DEFAULT false`
- `secret_history_depth INTEGER NOT NULL DEFAULT 256`

The model lives in `models/scan_policy.py`.

## Reporter ingest

`reporter/ingest.py` gains a `_secret_finding_rows(secrets_payload, ctx, head_sha)`
parser, and `ingest()` reads `/artifacts/secrets.json` when present:

- betterleaks emits a **JSON array** of findings (gitleaks schema). For each entry,
  map fields to a `secret_findings` row, compute `is_historical` from
  `head_sha` (read from `commit-sha.txt`), and normalize `validation_status`.
- Because `--redact` runs at the tool, `Match`/`Secret` arrive **pre-redacted** —
  the raw value never reaches the reporter. This is the strongest form of the
  security invariant below.
- Missing/empty `secrets.json` (secret scanning disabled, or zero findings) →
  zero rows, no error.
- Extend `IngestResult` and `CallbackPayload` (`schemas/scan.py`) with
  `secret_finding_count` and `verified_secret_count`. Insert into the new
  `secret_findings` table and the extended `scan_metrics` row.

## API & schemas

- `ScanResponse` (`schemas/scan.py`) gains `secret_finding_count` and
  `verified_secret_count`.
- New schema `SecretFinding` (`schemas/finding.py` or a new `secret.py`) matching
  the ClickHouse columns minus internal ids.
- New read endpoint, mirroring `listFindings`:
  `GET /scans/{scan_id}/secrets` (and/or `GET /repos/{repo_id}/secrets`), backed by
  ClickHouse, with pagination and a `validation_status` / `verified` filter.
  Lives alongside the existing findings routes.
- Scan-policy plumbing: the verify/enabled/depth flags are read when building the
  spec; exposing policy editing via the API is **out of scope** here (defaults +
  DB are sufficient for Phase 1).

## Web UI

Mirrors the existing scan-detail findings table
(`web/src/routes/scans/$id.tsx`), which uses TanStack Query + TanStack Table with
typed `api/client.ts` helpers and small UI primitives.

- **API client** (`web/src/api/client.ts`): add a `SecretFinding` type and a
  `listSecrets({ scanId, limit, offset, status })` function next to `listFindings`.
- **Scan detail page** (`web/src/routes/scans/$id.tsx`): add a **Secrets** section
  (a second table, or a Findings/Secrets tab toggle). Columns:
  - **Status** — a `VerifiedBadge` (new primitive in `components/ui/badge.tsx`):
    **red** for `verified` (live), neutral for `unverified`/`unknown`, amber for
    `error`.
  - **Rule** — `rule_id` (mono).
  - **Match** — the redacted preview (mono).
  - **Location** — `file:start_line`.
  - **Commit** — short sha, with a **"historical"** chip when `is_historical`.
  - **Committed** — `committed_at` via `formatDateTime`.
  - A filter row (`all / verified / unverified / error`) like the severity filter.
- **Counts:** add `secret_finding_count` and `verified_secret_count` to the scan
  summary `Field` grid.
- Reuse `Table`, `Button`, pagination, and loading/empty states verbatim from the
  findings table.

## Config & images

- `Settings` (`config.py`): `secret_scan_image` (pinned betterleaks tag),
  `secret_scan_enabled` (global default), `secret_history_depth` (default 256),
  and the egress network name used for verification.
- `docker-compose.yml` / `manifests/`: pull and pin the betterleaks image, the
  same way Syft/Grype images are pinned.
- Optional `/config/.betterleaks.toml`: a baseline (detect-only) config and a
  validation-enabled variant for verify mode, mounted into the stage.

## Error handling & edge cases

- **"Leaks found" must not fail the chain** — guaranteed by `--exit-code 0`; any
  non-zero is a real error and short-circuits to the reporter with `IPPON_FAILED`.
- **Verification egress blocked / timeout** → `validation_status = error`; the
  finding is still recorded (as unverified); the scan **succeeds**.
- **Large repos** — bounded by `--log-opts="-n {depth}"` and the existing
  `active_deadline_seconds` ceiling on the chain.
- **Artifacts teardown** — the per-scan `/artifacts` and `/workspace` volumes are
  already removed in the runner's `finally` block; the (redacted) report goes with
  them.
- **Logs** — betterleaks summary output captured in `logs_tail` must not contain
  raw values; `--redact` covers stdout/logs as well. Verify in tests.

## Security invariants

1. The **raw secret value is never persisted** to ClickHouse, S3, the callback, or
   any log. With tool-level `--redact`, the raw value never leaves the betterleaks
   container.
2. Verification network egress is **off by default** and only enabled when a scan
   policy opts in.
3. The fingerprint stored is the betterleaks **location** fingerprint, not a hash
   of the secret — no recoverable secret material is stored.

## Testing strategy

- **Unit:**
  - betterleaks JSON → `secret_findings` row mapping (fixture report), including
    `is_historical` and `validation_status` normalization.
  - `build_scan_job_spec` populates the secret flags from settings + policy.
  - Verify-vs-detect network selection logic in the runner.
- **Inline runner:** a fixture git repo with a **planted fake** secret (an
  obviously-test AWS key) committed in an *older* commit, then removed → assert it
  is detected, redacted, fingerprinted, and `is_historical = true`.
- **Integration (`docker` marker):** end-to-end against a small repo with a planted
  fake secret; assert a `secret_findings` row and the callback counts.
- **Invariant test:** assert the planted raw secret string never appears in any
  inserted ClickHouse row, the callback payload, or captured logs.
- **Web:** type-check the new client + table; basic render of the Secrets table.

## Phase 2 — ML (deferred)

Once Phase 1 produces labeled data — findings × verification outcomes × user
dismissals — an ML layer can:

- **Rank/triage** findings to cut false positives that betterleaks' BPE filtering
  doesn't catch, or
- **Detect format-less generic secrets** (custom tokens, passwords) that rule-based
  detection misses.

This is **justified by measured FP rates**, not built speculatively, and is **out
of scope** for this spec. betterleaks' built-in BPE token-efficiency filtering
already reduces noise, so Phase 2 targets the residual.

## Items to confirm against the pinned betterleaks version (implementation-time)

These do not change the architecture; confirm exact spelling/behavior when pinning
the image:

1. The precise mechanism to toggle validation on/off (appears config/rule-driven
   via the `validate` field rather than a single CLI flag).
2. That `--redact` with no percentage fully masks the secret in both the report and
   logs.
3. The exact JSON field names in the report (gitleaks schema: `RuleID`,
   `Description`, `Match`, `Secret`, `File`, `StartLine`, `EndLine`, `Commit`,
   `Author`, `Email`, `Date`, `Fingerprint`, `Tags`, and a validation/`valid`
   field).
