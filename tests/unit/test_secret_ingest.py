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
