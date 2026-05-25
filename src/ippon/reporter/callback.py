"""Signed HTTP callback to the API.

HMAC-SHA256 over the (JSON-serialized) body, with the per-scan callback
secret. The API verifies the same way; see
:func:`ippon.security.verify_hmac_sha256`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from typing import Any

import httpx

LOG = logging.getLogger("ippon.reporter.callback")

SIGNATURE_HEADER = "X-Ippon-Signature-256"


def sign_body(body: bytes, secret: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def post_callback(
    *,
    callback_url: str,
    callback_secret: str,
    payload: dict[str, Any],
    timeout: float = 10.0,
) -> int:
    """POST a signed callback. Returns the HTTP status code.

    Raises ``httpx.HTTPError`` on transport failure; does NOT raise on a
    non-2xx response — the caller decides whether to retry.
    """
    body = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    sig = sign_body(body, callback_secret)
    LOG.info("POST %s status=%s body_bytes=%d", callback_url, payload.get("status"), len(body))
    with httpx.Client(timeout=timeout) as client:
        r = client.post(
            callback_url,
            content=body,
            headers={
                "Content-Type": "application/json",
                SIGNATURE_HEADER: sig,
            },
        )
    LOG.info("callback %s → HTTP %d", callback_url, r.status_code)
    return r.status_code
