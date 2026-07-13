"""Unit tests for get_current_user and require_role dependencies (T043).

AsyncSession and DB are fully mocked — no live database required.
"""
import time
import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth.dependencies import _jti_cache, get_current_user, require_role
from src.auth.models import User
from src.auth.security import create_access_token

# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_user(**kwargs) -> User:
    defaults = {
        "id": uuid.uuid4(),
        "organization_id": uuid.uuid4(),
        "email": "user@example.com",
        "credential_hash": "x",
        "credential_type": "password",
        "role": "user",
        "status": "active",
        "failed_login_count": 0,
        "locked_until": None,
        "token_version": 1,
    }
    defaults.update(kwargs)
    u = MagicMock(spec=User)
    for k, v in defaults.items():
        setattr(u, k, v)
    return u


def _make_token(user: User, token_version: int | None = None) -> tuple[str, str]:
    """Return (encoded_jwt, jti) for the given user."""
    tv = token_version if token_version is not None else user.token_version
    token, jti = create_access_token(user.id, user.organization_id, user.role, tv)
    return token, jti


def _mock_session() -> AsyncSession:
    session = AsyncMock(spec=AsyncSession)
    return session


def _setup_db_mock(session: AsyncSession, user: User, org_status: str = "active") -> None:
    """Configure session.execute to return (user, org_status) for user-lookup queries
    and no RevokedToken for JTI revocation checks."""
    revoked_result = MagicMock()
    revoked_result.scalar_one_or_none.return_value = None  # JTI not revoked

    user_result = MagicMock()
    user_result.one_or_none.return_value = (user, org_status)

    session.execute.side_effect = [revoked_result, user_result]


# ── Valid JWT → active user ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_valid_jwt_returns_user() -> None:
    user = _make_user()
    token, jti = _make_token(user)

    # Ensure cache miss for this JTI
    _jti_cache.pop(jti, None)

    session = _mock_session()
    _setup_db_mock(session, user)

    with (
        patch("src.auth.dependencies.set_admin_context", new=AsyncMock()),
        patch("src.auth.dependencies.set_rls_context", new=AsyncMock()),
        patch("src.auth.dependencies.set_app_context", new=AsyncMock()),
    ):
        result = await get_current_user(token=token, db=session)

    assert result is user
    _jti_cache.pop(jti, None)


# ── Expired JWT raises 401 ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_expired_jwt_raises_401() -> None:
    import jwt as pyjwt

    from src.auth.config import auth_settings

    user = _make_user()
    payload = {
        "sub": str(user.id),
        "jti": str(uuid.uuid4()),
        "org": str(user.organization_id),
        "role": user.role,
        "tv": user.token_version,
        "iat": int((datetime.now(UTC) - timedelta(hours=2)).timestamp()),
        "exp": int((datetime.now(UTC) - timedelta(hours=1)).timestamp()),  # already expired
    }
    expired_token = pyjwt.encode(payload, auth_settings.JWT_SECRET, algorithm="HS256")

    session = _mock_session()

    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(token=expired_token, db=session)

    assert exc_info.value.status_code == 401


# ── token_version mismatch raises 401 ────────────────────────────────────────

@pytest.mark.asyncio
async def test_token_version_mismatch_raises_401() -> None:
    user = _make_user(token_version=2)
    token, jti = _make_token(user, token_version=1)  # stale version in token

    _jti_cache.pop(jti, None)

    session = _mock_session()
    _setup_db_mock(session, user)

    with (
        patch("src.auth.dependencies.set_admin_context", new=AsyncMock()),
        patch("src.auth.dependencies.set_rls_context", new=AsyncMock()),
        patch("src.auth.dependencies.set_app_context", new=AsyncMock()),
    ):
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(token=token, db=session)

    assert exc_info.value.status_code == 401
    _jti_cache.pop(jti, None)


# ── inactive user raises 401 ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_inactive_user_raises_401() -> None:
    user = _make_user(status="inactive")
    token, jti = _make_token(user)

    _jti_cache.pop(jti, None)

    session = _mock_session()
    _setup_db_mock(session, user)

    with (
        patch("src.auth.dependencies.set_admin_context", new=AsyncMock()),
        patch("src.auth.dependencies.set_rls_context", new=AsyncMock()),
        patch("src.auth.dependencies.set_app_context", new=AsyncMock()),
    ):
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(token=token, db=session)

    assert exc_info.value.status_code == 401
    _jti_cache.pop(jti, None)


# ── inactive org raises 401 ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_inactive_org_raises_401() -> None:
    user = _make_user(status="active")
    token, jti = _make_token(user)

    _jti_cache.pop(jti, None)

    session = _mock_session()
    _setup_db_mock(session, user, org_status="inactive")

    with (
        patch("src.auth.dependencies.set_admin_context", new=AsyncMock()),
        patch("src.auth.dependencies.set_rls_context", new=AsyncMock()),
        patch("src.auth.dependencies.set_app_context", new=AsyncMock()),
    ):
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(token=token, db=session)

    assert exc_info.value.status_code == 401
    _jti_cache.pop(jti, None)


# ── revoked JTI raises 401 ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_revoked_jti_raises_401() -> None:
    from src.auth.models import RevokedToken

    user = _make_user()
    token, jti = _make_token(user)

    _jti_cache.pop(jti, None)

    session = _mock_session()

    # First execute returns a RevokedToken (JTI was revoked)
    revoked_entry = MagicMock(spec=RevokedToken)
    revoked_result = MagicMock()
    revoked_result.scalar_one_or_none.return_value = revoked_entry
    session.execute.return_value = revoked_result

    with (
        patch("src.auth.dependencies.set_admin_context", new=AsyncMock()),
    ):
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(token=token, db=session)

    assert exc_info.value.status_code == 401
    _jti_cache.pop(jti, None)


# ── JTI cache: second call skips revoked_tokens DB check ─────────────────────

@pytest.mark.asyncio
async def test_jti_cache_skips_revoked_tokens_check_on_hit() -> None:
    user = _make_user()
    token, jti = _make_token(user)

    # Pre-populate cache so it's a cache hit
    _jti_cache[jti] = time.monotonic() + 30.0

    session = _mock_session()
    # Only user lookup result (no revoked_tokens lookup)
    user_result = MagicMock()
    user_result.one_or_none.return_value = (user, "active")
    session.execute.return_value = user_result

    with (
        patch("src.auth.dependencies.set_admin_context", new=AsyncMock()),
        patch("src.auth.dependencies.set_rls_context", new=AsyncMock()),
        patch("src.auth.dependencies.set_app_context", new=AsyncMock()),
    ):
        await get_current_user(token=token, db=session)

    # Only one DB call (user lookup), NOT two (revoked_tokens + user lookup)
    assert session.execute.call_count == 1
    _jti_cache.pop(jti, None)


# ── super_admin: org_status=None skips org check ─────────────────────────────

@pytest.mark.asyncio
async def test_super_admin_with_no_org_authenticates_successfully() -> None:
    user = _make_user(organization_id=None, role="super_admin")
    token, jti = _make_token(user)

    _jti_cache.pop(jti, None)

    session = _mock_session()
    _setup_db_mock(session, user, org_status=None)  # no org → org_status=None from LEFT JOIN

    with (
        patch("src.auth.dependencies.set_admin_context", new=AsyncMock()),
        patch("src.auth.dependencies.set_rls_context", new=AsyncMock()),
        patch("src.auth.dependencies.set_app_context", new=AsyncMock()),
    ):
        result = await get_current_user(token=token, db=session)

    assert result is user
    _jti_cache.pop(jti, None)


# ── require_role ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_require_role_admin_with_super_admin_raises_403() -> None:
    user = _make_user(role="super_admin")
    checker = require_role("admin")

    # role_checker takes current_user directly; call without FastAPI's DI
    with pytest.raises(HTTPException) as exc_info:
        await checker(current_user=user)

    assert exc_info.value.status_code == 403
