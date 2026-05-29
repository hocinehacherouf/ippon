"""Authentication primitives, HMAC helpers, and credential encryption.

For the scaffold, ``authenticate_dev_token`` is the only auth path: it
constant-time-compares a bearer token against ``Settings.ippon_dev_token``.
The function returns a :class:`Principal` so call sites can be written against
the eventual OIDC-issued claims model without churn.

The HMAC helpers here are used by inbound webhook verification (GitHub
``X-Hub-Signature-256``) and the reporter→API callback path.

``encrypt_secret`` / ``decrypt_secret`` are the at-rest crypto for
source-connection credentials (PATs) and per-connection webhook secrets.
They use symmetric Fernet with a key derived from
``Settings.ippon_secret_key``. ``credential_kid`` on the row records which
key version encrypted it (``CURRENT_KID``), so a future rotation can keep
old rows readable by mapping the kid to the retired key.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass

from cryptography.fernet import Fernet, InvalidToken


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


def generate_webhook_secret() -> str:
    """Mint a per-connection webhook secret (HMAC key / token / basic-auth pw)."""
    return secrets.token_urlsafe(32)


# --- credential encryption -------------------------------------------------

# Current key version. Rows store this in ``credential_kid``; a future
# rotation adds a new version and keeps the old key in ``_KEY_VERSIONS``
# so existing rows stay decryptable.
CURRENT_KID = "v1"


class CredentialDecryptionError(RuntimeError):
    """Raised when a stored secret can't be decrypted (wrong key / corrupt blob)."""


def derive_fernet_key(master: str) -> bytes:
    """Derive a urlsafe-base64 Fernet key from an arbitrary-length master string.

    Fernet requires a 32-byte urlsafe-base64 key; the configured
    ``ippon_secret_key`` is a free-form string, so we hash it to 32 bytes
    first. Deterministic — the same master always yields the same key.
    """
    digest = hashlib.sha256(master.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def _cipher_for_kid(kid: str, master: str) -> Fernet:
    """Return the Fernet cipher for a key version.

    Only ``CURRENT_KID`` exists today; this is the seam where a rotation
    would map an older kid to a previously-configured master key.
    """
    if kid != CURRENT_KID:
        raise CredentialDecryptionError(f"unknown credential key id: {kid!r}")
    return Fernet(derive_fernet_key(master))


def encrypt_secret(plaintext: str, master: str) -> tuple[bytes, str]:
    """Encrypt a secret; return ``(ciphertext, kid)``.

    Store both — the ciphertext in the ``*_blob`` column and the kid in
    ``credential_kid``.
    """
    cipher = _cipher_for_kid(CURRENT_KID, master)
    return cipher.encrypt(plaintext.encode("utf-8")), CURRENT_KID


def decrypt_secret(blob: bytes, kid: str, master: str) -> str:
    """Decrypt a secret previously produced by :func:`encrypt_secret`."""
    cipher = _cipher_for_kid(kid, master)
    try:
        return cipher.decrypt(blob).decode("utf-8")
    except InvalidToken as exc:
        raise CredentialDecryptionError("could not decrypt secret (wrong key?)") from exc
