"""ClickHouse + S3 ingest helpers for the reporter.

Parses Syft (CycloneDX) and Grype JSON outputs into the row shapes defined
in ``migrations/clickhouse/0001_initial.sql``. Network calls are kept in
this module so ``__main__`` reads as a workflow.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import boto3
import clickhouse_connect
from botocore.exceptions import ClientError

LOG = logging.getLogger("ippon.reporter.ingest")


@dataclass(frozen=True)
class IngestContext:
    scan_id: UUID
    org_id: UUID
    repo_id: UUID
    commit_sha: str
    scanned_at: datetime
    bucket: str
    object_key: str


@dataclass(frozen=True)
class IngestResult:
    syft_version: str
    grype_version: str
    grype_db_version: str | None
    sbom_sha256: str
    sbom_size_bytes: int
    dependency_count: int
    finding_count: int
    severity_counts: dict[str, int]
    secret_finding_count: int
    verified_secret_count: int


def build_object_key(org_id: UUID, repo_id: UUID, commit_sha: str) -> str:
    """Canonical S3 key for a scan's SBOM blob."""
    return f"sboms/{org_id}/{repo_id}/{commit_sha}.cdx.json"


def upload_sbom_to_s3(
    *,
    sbom_bytes: bytes,
    bucket: str,
    object_key: str,
    endpoint_url: str,
    access_key: str,
    secret_key: str,
) -> None:
    s3 = boto3.client(
        "s3",
        endpoint_url=endpoint_url,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name="us-east-1",  # RustFS ignores the region; required by boto.
    )
    try:
        s3.head_bucket(Bucket=bucket)
    except ClientError as exc:
        # 404 → bucket missing; create it. Anything else → re-raise.
        code = exc.response.get("Error", {}).get("Code")
        if code not in {"404", "NoSuchBucket", "NoSuchKey"}:
            raise
        LOG.info("bucket %s missing — creating", bucket)
        s3.create_bucket(Bucket=bucket)
    s3.put_object(
        Bucket=bucket,
        Key=object_key,
        Body=sbom_bytes,
        ContentType="application/vnd.cyclonedx+json",
    )
    LOG.info("uploaded SBOM to s3://%s/%s (%d bytes)", bucket, object_key, len(sbom_bytes))


def _ch_client(clickhouse_url: str) -> clickhouse_connect.driver.Client:
    from urllib.parse import urlparse

    parsed = urlparse(clickhouse_url)
    return clickhouse_connect.get_client(
        host=parsed.hostname or "clickhouse",
        port=parsed.port or 8123,
        username=parsed.username or "default",
        password=parsed.password or "",
        database=(parsed.path or "/").lstrip("/") or "default",
        secure=parsed.scheme == "https",
    )


def _syft_version(sbom: dict[str, Any]) -> str:
    """Pull the Syft version out of a CycloneDX SBOM's ``metadata.tools``."""
    tools = sbom.get("metadata", {}).get("tools", {})
    # CycloneDX 1.5+ shape: tools is an object with a ``components`` list.
    components = tools.get("components") if isinstance(tools, dict) else None
    if isinstance(components, list):
        for c in components:
            if (c.get("name") or "").lower() == "syft":
                return str(c.get("version", "unknown"))
    # Older shape: tools is a list of tool dicts.
    if isinstance(tools, list):
        for t in tools:
            if (t.get("name") or "").lower() == "syft":
                return str(t.get("version", "unknown"))
    return "unknown"


def _grype_version(findings_payload: dict[str, Any]) -> tuple[str, str | None]:
    """Return ``(grype_version, db_built_at)`` from a Grype JSON output."""
    descriptor = findings_payload.get("descriptor", {})
    version = str(descriptor.get("version", "unknown"))
    db = descriptor.get("db", {})
    db_built = db.get("built") if isinstance(db, dict) else None
    return version, str(db_built) if db_built is not None else None


def _purl(component: dict[str, Any]) -> str:
    return str(component.get("purl") or "")


def _component_license(component: dict[str, Any]) -> str:
    licenses = component.get("licenses") or []
    names: list[str] = []
    for entry in licenses:
        lic = entry.get("license") if isinstance(entry, dict) else None
        if isinstance(lic, dict):
            name = lic.get("id") or lic.get("name")
            if name:
                names.append(str(name))
        elif isinstance(entry, dict):
            expr = entry.get("expression")
            if expr:
                names.append(str(expr))
    return ", ".join(names)


def _coerce_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _ecosystem_from_purl(purl: str) -> str:
    # purl: ``pkg:<type>/<name>@<version>`` — the type segment is the ecosystem.
    if not purl.startswith("pkg:"):
        return ""
    rest = purl[4:]
    return rest.split("/", 1)[0] if "/" in rest else rest


def _dependency_rows(sbom: dict[str, Any], ctx: IngestContext) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for component in sbom.get("components", []):
        purl = _purl(component)
        rows.append(
            {
                "scan_id": ctx.scan_id,
                "org_id": ctx.org_id,
                "repo_id": ctx.repo_id,
                "commit_sha": ctx.commit_sha,
                "purl": purl,
                "name": str(component.get("name") or ""),
                "version": str(component.get("version") or ""),
                "ecosystem": _ecosystem_from_purl(purl),
                "scope": str(component.get("scope") or "required"),
                "license": _component_license(component),
                "scanned_at": ctx.scanned_at,
            }
        )
    return rows


_SEVERITY_CANON = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "negligible": "negligible",
    "unknown": "unknown",
}


def _finding_rows(
    findings: dict[str, Any], ctx: IngestContext
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    rows: list[dict[str, Any]] = []
    counts: dict[str, int] = dict.fromkeys(_SEVERITY_CANON.values(), 0)
    for match in findings.get("matches", []):
        vuln = match.get("vulnerability", {}) or {}
        artifact = match.get("artifact", {}) or {}
        cve_id = str(vuln.get("id") or "")
        severity = _SEVERITY_CANON.get(str(vuln.get("severity") or "").lower(), "unknown")
        fix = vuln.get("fix") or {}
        cvss = (vuln.get("cvss") or [{}])[0]
        cvss_metrics = cvss.get("metrics") or {}
        rows.append(
            {
                "scan_id": ctx.scan_id,
                "org_id": ctx.org_id,
                "repo_id": ctx.repo_id,
                "commit_sha": ctx.commit_sha,
                "cve_id": cve_id,
                "purl": str(artifact.get("purl") or ""),
                "name": str(artifact.get("name") or ""),
                "version": str(artifact.get("version") or ""),
                "severity": severity,
                "fix_state": str(fix.get("state") or "unknown"),
                "fix_versions": list(fix.get("versions") or []),
                "description": str(vuln.get("description") or ""),
                "cvss_score": _coerce_float(cvss_metrics.get("baseScore")),
                "cvss_vector": str(cvss.get("vector") or ""),
                "matcher": str((match.get("matchDetails") or [{}])[0].get("matcher") or ""),
                "scanned_at": ctx.scanned_at,
            }
        )
        counts[severity] += 1
    return rows, counts


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
                "is_historical": commit != head_sha,
                "scanned_at": ctx.scanned_at,
            }
        )
    return rows, verified_count


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
    """End-to-end ingest: upload SBOM blob → insert CH rows → return summary."""
    sbom_bytes = sbom_path.read_bytes()
    sbom = json.loads(sbom_bytes.decode("utf-8"))
    findings_payload = json.loads(findings_path.read_bytes().decode("utf-8"))

    sbom_sha256 = hashlib.sha256(sbom_bytes).hexdigest()
    syft_version = _syft_version(sbom)
    grype_version, grype_db_built = _grype_version(findings_payload)
    spec_version = str(sbom.get("specVersion") or "1.6")

    upload_sbom_to_s3(
        sbom_bytes=sbom_bytes,
        bucket=ctx.bucket,
        object_key=ctx.object_key,
        endpoint_url=s3_endpoint_url,
        access_key=s3_access_key,
        secret_key=s3_secret_key,
    )

    client = _ch_client(clickhouse_url)
    try:
        # sboms
        client.insert(
            "sboms",
            [
                [
                    ctx.scan_id,
                    ctx.org_id,
                    ctx.repo_id,
                    ctx.commit_sha,
                    ctx.scanned_at,
                    "cyclonedx-json",
                    spec_version,
                    syft_version,
                    sbom_sha256,
                    len(sbom_bytes),
                    ctx.object_key,
                    sbom_bytes.decode("utf-8"),
                ]
            ],
            column_names=[
                "scan_id",
                "org_id",
                "repo_id",
                "commit_sha",
                "scanned_at",
                "format",
                "spec_version",
                "syft_version",
                "sbom_sha256",
                "sbom_size_bytes",
                "object_key",
                "sbom_json",
            ],
        )

        dep_rows = _dependency_rows(sbom, ctx)
        if dep_rows:
            client.insert(
                "dependencies",
                [list(r.values()) for r in dep_rows],
                column_names=list(dep_rows[0].keys()),
            )

        find_rows, severity_counts = _finding_rows(findings_payload, ctx)
        if find_rows:
            client.insert(
                "findings",
                [list(r.values()) for r in find_rows],
                column_names=list(find_rows[0].keys()),
            )

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

        duration = (datetime.now(UTC) - scan_started_at).total_seconds()
        client.insert(
            "scan_metrics",
            [
                [
                    ctx.scan_id,
                    ctx.org_id,
                    ctx.repo_id,
                    ctx.commit_sha,
                    duration,
                    0.0,
                    0.0,
                    len(dep_rows),
                    len(find_rows),
                    severity_counts.get("critical", 0),
                    severity_counts.get("high", 0),
                    severity_counts.get("medium", 0),
                    severity_counts.get("low", 0),
                    ctx.scanned_at,
                    secret_finding_count,
                    verified_secret_count,
                ]
            ],
            column_names=[
                "scan_id",
                "org_id",
                "repo_id",
                "commit_sha",
                "duration_seconds",
                "syft_duration_seconds",
                "grype_duration_seconds",
                "dependency_count",
                "finding_count",
                "critical_count",
                "high_count",
                "medium_count",
                "low_count",
                "scanned_at",
                "secret_finding_count",
                "verified_secret_count",
            ],
        )
    finally:
        client.close()

    return IngestResult(
        syft_version=syft_version,
        grype_version=grype_version,
        grype_db_version=grype_db_built,
        sbom_sha256=sbom_sha256,
        sbom_size_bytes=len(sbom_bytes),
        dependency_count=len(dep_rows),
        finding_count=len(find_rows),
        severity_counts=severity_counts,
        secret_finding_count=secret_finding_count,
        verified_secret_count=verified_secret_count,
    )
