-- ippon ClickHouse schema v1
--
-- Statements in this file are separated by semicolons and applied in order by
-- ``apply.py``. Every CREATE uses ``IF NOT EXISTS`` so the file is safe to
-- re-run against a partial state, though the applier already guards via
-- ``schema_versions``.
--
-- Versioning: the integer prefix in the filename (here ``0001``) is the
-- version number; the applier records it in ``schema_versions`` after the
-- whole file succeeds.

-- ----------------------------------------------------------------------
-- sboms — one row per scan; stores the full CycloneDX JSON + metadata.
-- ----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sboms (
    scan_id          UUID,
    org_id           UUID,
    repo_id          UUID,
    commit_sha       String,
    scanned_at       DateTime,
    format           LowCardinality(String),    -- 'cyclonedx-json'
    spec_version     LowCardinality(String),    -- e.g. '1.6'
    syft_version     String,
    sbom_sha256      String,
    sbom_size_bytes  UInt64,
    object_key       String,                    -- S3 key in RustFS
    sbom_json        String CODEC(ZSTD(3))      -- full CycloneDX blob
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(scanned_at)
ORDER BY (org_id, repo_id, scanned_at);

-- ----------------------------------------------------------------------
-- dependencies — one row per (scan, component); fan-out of the SBOM.
-- ----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dependencies (
    scan_id      UUID,
    org_id       UUID,
    repo_id      UUID,
    commit_sha   String,
    purl         String,
    name         LowCardinality(String),
    version      String,
    ecosystem    LowCardinality(String),    -- npm/pypi/maven/...
    scope        LowCardinality(String),    -- runtime/dev/test
    license      LowCardinality(String),
    scanned_at   DateTime
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(scanned_at)
ORDER BY (org_id, repo_id, purl, scan_id);

-- ----------------------------------------------------------------------
-- findings — one row per (scan, cve, component) matched by Grype.
-- ----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS findings (
    scan_id        UUID,
    org_id         UUID,
    repo_id        UUID,
    commit_sha     String,
    cve_id         LowCardinality(String),
    purl           String,
    name           LowCardinality(String),
    version        String,
    severity       LowCardinality(String),  -- critical/high/medium/low/negligible/unknown
    fix_state      LowCardinality(String),  -- fixed/not-fixed/wont-fix/unknown
    fix_versions   Array(String),
    description    String CODEC(ZSTD(3)),
    cvss_score     Nullable(Float32),
    cvss_vector    String,
    matcher        LowCardinality(String),  -- grype matcher name
    scanned_at     DateTime
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(scanned_at)
ORDER BY (org_id, severity, cve_id, scan_id);

-- ----------------------------------------------------------------------
-- scan_metrics — one row per scan; cheap top-level aggregates.
-- ----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_metrics (
    scan_id                 UUID,
    org_id                  UUID,
    repo_id                 UUID,
    commit_sha              String,
    duration_seconds        Float32,
    syft_duration_seconds   Float32,
    grype_duration_seconds  Float32,
    dependency_count        UInt32,
    finding_count           UInt32,
    critical_count          UInt32,
    high_count              UInt32,
    medium_count            UInt32,
    low_count               UInt32,
    scanned_at              DateTime
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(scanned_at)
ORDER BY (org_id, repo_id, scanned_at);

-- ----------------------------------------------------------------------
-- vex_statements — VEX is the one mutable dataset; edits insert a new row
-- with the same id and a fresh ``updated_at``; soft-deletes set
-- ``is_deleted=1``. Reads MUST use FINAL or argMax(..., updated_at) to
-- collapse to current state. See ``ippon.clickhouse`` module docstring.
-- ----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS vex_statements (
    id                UUID,
    org_id            UUID,
    repo_id           Nullable(UUID),
    cve_id            LowCardinality(String),
    purl              String,
    status            LowCardinality(String),  -- not_affected/affected/fixed/under_investigation
    justification     String,
    impact_statement  String,
    created_by        UUID,
    created_at        DateTime,
    updated_at        DateTime,
    expires_at        Nullable(DateTime),
    is_deleted        UInt8 DEFAULT 0
) ENGINE = ReplacingMergeTree(updated_at, is_deleted)
ORDER BY (org_id, cve_id, purl, id);
