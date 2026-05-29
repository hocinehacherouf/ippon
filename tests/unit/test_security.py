"""Unit tests for bearer auth, HMAC helpers, and credential encryption."""

from __future__ import annotations

import pytest

from ippon.security import (
    CURRENT_KID,
    CredentialDecryptionError,
    authenticate_dev_token,
    compute_hmac_sha256,
    constant_time_str_eq,
    decrypt_secret,
    encrypt_secret,
    generate_webhook_secret,
    verify_hmac_sha256,
)


def test_authenticate_dev_token_accepts_match() -> None:
    principal = authenticate_dev_token("secret-token", "secret-token")
    assert principal is not None
    assert principal.subject == "dev"


def test_authenticate_dev_token_rejects_mismatch() -> None:
    assert authenticate_dev_token("wrong", "secret-token") is None


def test_authenticate_dev_token_rejects_empty() -> None:
    assert authenticate_dev_token("", "secret-token") is None
    assert authenticate_dev_token("anything", "") is None


def test_hmac_round_trip() -> None:
    secret = b"webhook-secret"
    body = b'{"action":"opened"}'
    sig = compute_hmac_sha256(secret, body)
    assert verify_hmac_sha256(sig, body, secret)
    assert verify_hmac_sha256(f"sha256={sig}", body, secret)


def test_hmac_rejects_wrong_signature() -> None:
    assert not verify_hmac_sha256("deadbeef" * 8, b"body", b"secret")


def test_hmac_rejects_empty_signature() -> None:
    assert not verify_hmac_sha256("", b"body", b"secret")


def test_constant_time_str_eq() -> None:
    assert constant_time_str_eq("abc", "abc")
    assert not constant_time_str_eq("abc", "abd")
    assert not constant_time_str_eq("", "abc")


# --- credential encryption -------------------------------------------------


def test_encrypt_decrypt_round_trip() -> None:
    master = "a-master-key"
    blob, kid = encrypt_secret("ghp_supersecretpat", master)
    assert kid == CURRENT_KID
    assert isinstance(blob, bytes)
    assert b"ghp_supersecretpat" not in blob  # actually encrypted
    assert decrypt_secret(blob, kid, master) == "ghp_supersecretpat"


def test_decrypt_with_wrong_master_fails() -> None:
    blob, kid = encrypt_secret("token", "master-A")
    with pytest.raises(CredentialDecryptionError):
        decrypt_secret(blob, kid, "master-B")


def test_decrypt_unknown_kid_fails() -> None:
    blob, _ = encrypt_secret("token", "master")
    with pytest.raises(CredentialDecryptionError):
        decrypt_secret(blob, "v999", "master")


def test_encrypt_is_nondeterministic() -> None:
    # Fernet embeds a random IV + timestamp, so two encryptions differ.
    master = "master"
    a, _ = encrypt_secret("same", master)
    b, _ = encrypt_secret("same", master)
    assert a != b
    assert decrypt_secret(a, CURRENT_KID, master) == decrypt_secret(b, CURRENT_KID, master)


def test_generate_webhook_secret_is_unique_and_urlsafe() -> None:
    s1 = generate_webhook_secret()
    s2 = generate_webhook_secret()
    assert s1 != s2
    assert len(s1) >= 32
    assert s1.replace("-", "").replace("_", "").isalnum()
