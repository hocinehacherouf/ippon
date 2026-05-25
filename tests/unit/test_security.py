"""Unit tests for bearer auth and HMAC helpers."""

from __future__ import annotations

from ippon.security import (
    authenticate_dev_token,
    compute_hmac_sha256,
    constant_time_str_eq,
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
