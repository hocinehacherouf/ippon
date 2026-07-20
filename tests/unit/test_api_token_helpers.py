from __future__ import annotations

from ippon.security import hash_token_secret, mint_api_token, parse_api_token


def test_mint_then_parse_round_trips() -> None:
    full, prefix, secret_hash = mint_api_token()
    assert full.startswith("ippon_pat_")
    parsed = parse_api_token(full)
    assert parsed is not None
    p_prefix, p_secret = parsed
    assert p_prefix == prefix
    assert hash_token_secret(p_secret) == secret_hash


def test_parse_rejects_garbage() -> None:
    assert parse_api_token("nope") is None
    assert parse_api_token("ippon_pat_") is None
    assert parse_api_token("ippon_pat_onlyprefix") is None


def test_hash_is_deterministic_and_wrong_secret_differs() -> None:
    _, _, h = mint_api_token()
    assert hash_token_secret("different") != h


def test_parse_preserves_underscores_and_hyphens_in_secret() -> None:
    token = "ippon_pat_" + "a" * 12 + "_foo_bar-baz_qux"
    assert parse_api_token(token) == ("a" * 12, "foo_bar-baz_qux")


def test_parse_rejects_trailing_separator_empty_secret() -> None:
    assert parse_api_token("ippon_pat_" + "a" * 12 + "_") is None
