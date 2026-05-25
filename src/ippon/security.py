"""Authentication primitives and HMAC helpers.

For the scaffold, ``authenticate_dev_token`` is the only auth path: it
constant-time-compares a bearer token against ``Settings.ippon_dev_token``.
The function returns a :class:`Principal` so call sites can be written against
the eventual OIDC-issued claims model without churn.

The HMAC helpers here are used by inbound webhook verification (GitHub
``X-Hub-Signature-256``) and the reporter→API callback path in M6.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass


@dataclass(frozen=True)
class Principal:
    """The authenticated caller. Mirrors the shape of OIDC claims we'll surface later."""

    subject: str
    email: str | None
    is_service: bool


# --- bearer ---------------------------------------------------------------

DEV_PRINCIPAL = Principal(subject="dev", email="dev@ippon.local", is_service=True)


def authenticate_dev_token(presented: str, expected: str) -> Principal | None:
    """Constant-time compare; return the dev principal on success, ``None`` on failure."""
    if not presented or not expected:
        return None
    if not secrets.compare_digest(presented.encode("utf-8"), expected.encode("utf-8")):
        return None
    return DEV_PRINCIPAL


# --- HMAC -----------------------------------------------------------------


def compute_hmac_sha256(secret: bytes, body: bytes) -> str:
    """Hex digest of HMAC-SHA256(secret, body)."""
    return hmac.new(secret, body, hashlib.sha256).hexdigest()


def verify_hmac_sha256(presented: str, body: bytes, secret: bytes) -> bool:
    """Constant-time verify a hex HMAC-SHA256 signature.

    Accepts either a bare hex digest or a ``sha256=<hex>`` prefix (GitHub style).
    """
    if not presented:
        return False
    if presented.startswith("sha256="):
        presented = presented[len("sha256=") :]
    expected = compute_hmac_sha256(secret, body)
    return secrets.compare_digest(presented.lower(), expected)


def constant_time_str_eq(a: str, b: str) -> bool:
    """Wrapper around ``secrets.compare_digest`` for plain string equality."""
    if not a or not b:
        return False
    return secrets.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def generate_callback_secret() -> str:
    """Mint a per-scan HMAC secret for the reporter→API callback."""
    return secrets.token_urlsafe(32)
