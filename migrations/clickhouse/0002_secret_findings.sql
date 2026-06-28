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
