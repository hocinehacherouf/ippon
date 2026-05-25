"""Reporter — runs inside the scan job's final container.

Reads ``/artifacts/sbom.json`` + ``/artifacts/findings.json``, uploads the SBOM
to S3, ingests rows into ClickHouse, posts an HMAC-signed callback to the API.
On the failure path (``IPPON_FAILED=1``), skips ingest and posts a failure
callback. This is the only component that writes to ClickHouse on the
scan write-path.
"""
