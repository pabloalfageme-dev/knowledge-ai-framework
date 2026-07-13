import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import bcrypt
import jwt

from src.auth.config import auth_settings

# JWT claim key for token version (used to detect revocation)
_TV_CLAIM = "tv"


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def generate_api_key() -> tuple[str, str]:
    """Return (raw_key, sha256_hash). raw_key is shown once; store only the hash."""
    raw = str(uuid.uuid4())
    hashed = hashlib.sha256(raw.encode()).hexdigest()
    return raw, hashed


def hash_refresh_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def create_access_token(
    user_id: uuid.UUID,
    org_id: uuid.UUID | None,
    role: str,
    token_version: int,
) -> tuple[str, str]:
    """Return (encoded_jwt, jti). jti is stored for potential future revocation."""
    jti = str(uuid.uuid4())
    now = datetime.now(UTC)
    expire = now + timedelta(seconds=auth_settings.ACCESS_TOKEN_EXPIRE_SECONDS)
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "jti": jti,
        "org": str(org_id) if org_id else None,
        "role": role,
        _TV_CLAIM: token_version,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    token = jwt.encode(payload, auth_settings.JWT_SECRET, algorithm="HS256")
    return token, jti


def decode_access_token(token: str) -> dict[str, Any]:
    """Decode and verify a JWT. Raises jwt.PyJWTError on any failure."""
    return jwt.decode(token, auth_settings.JWT_SECRET, algorithms=["HS256"])
