"""Reporter entry point.

Reads everything from environment variables (set by the runner when creating
the reporter container). Exits 0 on success, non-zero on partial failure —
always attempts the callback POST so the API learns about the outcome.
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from ippon.reporter.callback import post_callback
from ippon.reporter.ingest import IngestContext, build_object_key, ingest


def _env_bool(key: str, default: bool = False) -> bool:
    return os.environ.get(key, "0" if not default else "1").lower() in {"1", "true", "yes"}


def _env_required(key: str) -> str:
    val = os.environ.get(key)
    if not val:
        raise SystemExit(f"reporter: missing required env {key}")
    return val


def _main() -> int:
    logging.basicConfig(
        level=os.environ.get("IPPON_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    log = logging.getLogger("ippon.reporter")

    scan_id = UUID(_env_required("IPPON_SCAN_ID"))
    org_id = UUID(_env_required("IPPON_ORG_ID"))
    repo_id = UUID(_env_required("IPPON_REPO_ID"))
    callback_url = _env_required("IPPON_CALLBACK_URL")
    callback_secret = _env_required("IPPON_CALLBACK_SECRET")
    failed = _env_bool("IPPON_FAILED")
    failed_step = os.environ.get("IPPON_FAILED_STEP")
    failed_reason = os.environ.get("IPPON_FAILED_REASON")

    sbom_path = Path(os.environ.get("IPPON_SBOM_PATH", "/artifacts/sbom.json"))
    findings_path = Path(os.environ.get("IPPON_FINDINGS_PATH", "/artifacts/findings.json"))
    commit_sha_path = Path(os.environ.get("IPPON_COMMIT_SHA_PATH", "/artifacts/commit-sha.txt"))

    scanned_at = datetime.now(UTC)
    started_at_iso = os.environ.get("IPPON_SCAN_STARTED_AT")
    scan_started_at = datetime.fromisoformat(started_at_iso) if started_at_iso else scanned_at

    commit_sha = "unknown"
    if commit_sha_path.exists():
        commit_sha = commit_sha_path.read_text(encoding="utf-8").strip() or "unknown"

    # Failure short-circuit: post a failure callback and bail.
    if failed:
        log.warning(
            "running in FAILED mode (step=%s reason=%s) — skipping ingest",
            failed_step,
            failed_reason,
        )
        payload: dict[str, object] = {
            "scan_id": str(scan_id),
            "status": "failed",
            "failed_step": failed_step,
            "error_message": failed_reason,
            "commit_sha": commit_sha if commit_sha != "unknown" else None,
            "finished_at": datetime.now(UTC).isoformat(),
        }
        post_callback(
            callback_url=callback_url,
            callback_secret=callback_secret,
            payload=payload,
        )
        return 1

    # Happy path.
    bucket = _env_required("S3_BUCKET")
    object_key = build_object_key(org_id, repo_id, commit_sha)
    ctx = IngestContext(
        scan_id=scan_id,
        org_id=org_id,
        repo_id=repo_id,
        commit_sha=commit_sha,
        scanned_at=scanned_at,
        bucket=bucket,
        object_key=object_key,
    )

    callback_status = "succeeded"
    error_message: str | None = None
    ingest_result = None
    try:
        ingest_result = ingest(
            sbom_path=sbom_path,
            findings_path=findings_path,
            ctx=ctx,
            clickhouse_url=_env_required("CLICKHOUSE_URL"),
            s3_endpoint_url=_env_required("S3_ENDPOINT_URL"),
            s3_access_key=_env_required("AWS_ACCESS_KEY_ID"),
            s3_secret_key=_env_required("AWS_SECRET_ACCESS_KEY"),
            scan_started_at=scan_started_at,
        )
    except Exception as exc:  # pylint: disable=broad-except
        log.exception("ingest failed")
        callback_status = "failed"
        error_message = f"reporter ingest error: {exc!s}"

    payload = {
        "scan_id": str(scan_id),
        "status": callback_status,
        "commit_sha": commit_sha if commit_sha != "unknown" else None,
        "object_key": object_key if callback_status == "succeeded" else None,
        "sbom_sha256": ingest_result.sbom_sha256 if ingest_result else None,
        "sbom_size_bytes": ingest_result.sbom_size_bytes if ingest_result else None,
        "syft_version": ingest_result.syft_version if ingest_result else None,
        "grype_version": ingest_result.grype_version if ingest_result else None,
        "grype_db_version": ingest_result.grype_db_version if ingest_result else None,
        "dependency_count": ingest_result.dependency_count if ingest_result else 0,
        "finding_count": ingest_result.finding_count if ingest_result else 0,
        "severity_counts": ingest_result.severity_counts if ingest_result else {},
        "error_message": error_message,
        "finished_at": datetime.now(UTC).isoformat(),
    }

    http_status = post_callback(
        callback_url=callback_url,
        callback_secret=callback_secret,
        payload=payload,
    )
    if http_status >= 400:
        log.error("callback returned HTTP %d", http_status)
        return 2
    return 0 if callback_status == "succeeded" else 1


if __name__ == "__main__":
    sys.exit(_main())
