"""Unit tests for src/auth/security.py (T028)."""
import hashlib
import uuid

import jwt
import pytest

from src.auth.security import (
    create_access_token,
    decode_access_token,
    generate_api_key,
    hash_password,
    hash_refresh_token,
    verify_password,
)


def test_hash_and_verify_password_roundtrip():
    plain = "S3cur3P@ssword!"
    hashed = hash_password(plain)
    assert hashed != plain
    assert verify_password(plain, hashed)


def test_verify_password_wrong_input_returns_false():
    hashed = hash_password("correct")
    assert not verify_password("wrong", hashed)


def test_generate_api_key_returns_distinct_pair():
    raw, hashed = generate_api_key()
    assert raw != hashed
    assert len(raw) == 36  # UUID string length
    assert len(hashed) == 64  # SHA-256 hex digest


def test_generate_api_key_hash_is_sha256_of_raw():
    raw, hashed = generate_api_key()
    assert hashed == hashlib.sha256(raw.encode()).hexdigest()


def test_generate_api_key_produces_unique_pairs():
    raw1, _ = generate_api_key()
    raw2, _ = generate_api_key()
    assert raw1 != raw2


def test_hash_refresh_token_is_sha256():
    raw = str(uuid.uuid4())
    result = hash_refresh_token(raw)
    assert result == hashlib.sha256(raw.encode()).hexdigest()


def test_create_and_decode_access_token_roundtrip():
    user_id = uuid.uuid4()
    org_id = uuid.uuid4()
    token, jti = create_access_token(user_id, org_id, "admin", 1)

    payload = decode_access_token(token)
    assert payload["sub"] == str(user_id)
    assert payload["org"] == str(org_id)
    assert payload["role"] == "admin"
    assert payload["tv"] == 1
    assert payload["jti"] == jti


def test_create_access_token_with_null_org():
    user_id = uuid.uuid4()
    token, _ = create_access_token(user_id, None, "user", 1)
    payload = decode_access_token(token)
    assert payload["org"] is None


def test_decode_access_token_raises_on_expired():
    from datetime import UTC, datetime, timedelta

    from src.auth.config import auth_settings

    user_id = uuid.uuid4()
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "jti": str(uuid.uuid4()),
        "org": None,
        "role": "user",
        "tv": 1,
        "iat": int((now - timedelta(seconds=10)).timestamp()),
        "exp": int((now - timedelta(seconds=5)).timestamp()),
    }
    expired_token = jwt.encode(payload, auth_settings.JWT_SECRET, algorithm="HS256")

    with pytest.raises(jwt.PyJWTError):
        decode_access_token(expired_token)


def test_decode_access_token_raises_on_wrong_secret():
    user_id = uuid.uuid4()
    token, _ = create_access_token(user_id, None, "user", 1)

    import jwt as _jwt

    tampered = _jwt.encode({"sub": str(user_id)}, "wrong-secret", algorithm="HS256")
    with pytest.raises(_jwt.PyJWTError):
        decode_access_token(tampered)


def test_token_version_survives_roundtrip():
    user_id = uuid.uuid4()
    org_id = uuid.uuid4()
    for tv in [1, 5, 42]:
        token, _ = create_access_token(user_id, org_id, "user", tv)
        payload = decode_access_token(token)
        assert payload["tv"] == tv
