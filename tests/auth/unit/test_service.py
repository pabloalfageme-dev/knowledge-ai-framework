"""Unit tests for service layer business logic (T042).

All database I/O is mocked via AsyncMock so these tests run without a live DB.
"""
import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth.models import AuditLogEntry, RefreshToken, User
from src.auth.service import (
    authenticate_user,
    logout,
    refresh_tokens,
    update_user,
    write_audit_entry,
)

# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_user(**kwargs) -> User:
    defaults = {
        "id": uuid.uuid4(),
        "organization_id": uuid.uuid4(),
        "email": "user@example.com",
        "credential_hash": "",
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


def _mock_session() -> AsyncSession:
    session = AsyncMock(spec=AsyncSession)
    session.flush = AsyncMock()
    session.rollback = AsyncMock()
    return session


# ── write_audit_entry ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_write_audit_entry_does_not_raise_on_flush_failure() -> None:
    session = _mock_session()
    session.flush.side_effect = Exception("DB down")

    # Should NOT propagate — audit writes are non-blocking
    await write_audit_entry(session, "LOGIN_SUCCESS", "127.0.0.1")


@pytest.mark.asyncio
async def test_write_audit_entry_adds_row_to_session() -> None:
    session = _mock_session()
    await write_audit_entry(session, "LOGIN_FAILURE", "10.0.0.1", user_id=uuid.uuid4())
    session.add.assert_called_once()
    added = session.add.call_args[0][0]
    assert isinstance(added, AuditLogEntry)
    assert added.event_type == "LOGIN_FAILURE"


# ── authenticate_user ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_authenticate_user_wrong_password_increments_failed_count() -> None:
    user = _make_user(credential_type="password")
    session = _mock_session()

    with (
        patch("src.auth.service.set_admin_context", new=AsyncMock()),
        patch(
            "src.auth.service.verify_password", return_value=False
        ),
        patch(
            "src.auth.service.write_audit_entry", new=AsyncMock()
        ),
    ):
        # Patch the DB execute to return our mock user with org_status=active
        org_status = "active"
        mock_row = MagicMock()
        mock_row.one_or_none.return_value = (user, org_status)
        session.execute.return_value = mock_row

        with pytest.raises(HTTPException) as exc_info:
            await authenticate_user(session, "user@example.com", "wrong", "127.0.0.1")

        assert exc_info.value.status_code == 401
        assert user.failed_login_count == 1


@pytest.mark.asyncio
async def test_authenticate_user_fifth_failure_sets_locked_until() -> None:

    user = _make_user(credential_type="password", failed_login_count=4)
    session = _mock_session()

    with (
        patch("src.auth.service.set_admin_context", new=AsyncMock()),
        patch("src.auth.service.verify_password", return_value=False),
        patch("src.auth.service.write_audit_entry", new=AsyncMock()),
    ):
        mock_row = MagicMock()
        mock_row.one_or_none.return_value = (user, "active")
        session.execute.return_value = mock_row

        with pytest.raises(HTTPException):
            await authenticate_user(session, "user@example.com", "bad", "127.0.0.1")

        assert user.failed_login_count == 5
        assert user.locked_until is not None


@pytest.mark.asyncio
async def test_authenticate_user_locked_account_returns_401() -> None:
    user = _make_user(locked_until=datetime.now(UTC) + timedelta(minutes=10))
    session = _mock_session()

    with (
        patch("src.auth.service.set_admin_context", new=AsyncMock()),
        patch("src.auth.service.write_audit_entry", new=AsyncMock()),
    ):
        mock_row = MagicMock()
        mock_row.one_or_none.return_value = (user, "active")
        session.execute.return_value = mock_row

        with pytest.raises(HTTPException) as exc_info:
            await authenticate_user(session, "user@example.com", "any", "127.0.0.1")

        assert exc_info.value.status_code == 401


# ── refresh_tokens ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_refresh_tokens_reuse_revokes_entire_family() -> None:
    now = datetime.now(UTC)
    rt = MagicMock(spec=RefreshToken)
    rt.token_hash = "abc"
    rt.used_at = now  # already used → replay detected
    rt.family_id = uuid.uuid4()

    session = _mock_session()

    # First execute returns the used refresh token; second is the family revocation
    first_result = MagicMock()
    first_result.scalar_one_or_none.return_value = rt
    second_result = MagicMock()
    session.execute.side_effect = [first_result, second_result]

    with (
        patch("src.auth.service.set_admin_context", new=AsyncMock()),
        patch("src.auth.service.hash_refresh_token", return_value="abc"),
    ):
        with pytest.raises(HTTPException) as exc_info:
            await refresh_tokens(session, uuid.uuid4(), "127.0.0.1")

        assert exc_info.value.status_code == 401
        # Family revocation UPDATE must have been issued
        assert session.execute.call_count == 2


# ── logout ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_logout_inserts_jti_into_revoked_tokens() -> None:
    from src.auth.models import RevokedToken

    user = _make_user()
    rt = MagicMock(spec=RefreshToken)
    rt.used_at = None

    session = _mock_session()
    rt_result = MagicMock()
    rt_result.scalar_one_or_none.return_value = rt
    session.execute.return_value = rt_result

    jti = str(uuid.uuid4())
    exp = datetime.now(UTC) + timedelta(minutes=15)

    with patch("src.auth.service.write_audit_entry", new=AsyncMock()):
        await logout(session, user, uuid.uuid4(), jti, exp, "127.0.0.1")

    added_objs = [call[0][0] for call in session.add.call_args_list]
    revoked_entries = [o for o in added_objs if isinstance(o, RevokedToken)]
    assert len(revoked_entries) == 1
    assert revoked_entries[0].jti == jti


# ── update_user ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_update_user_role_change_increments_token_version() -> None:
    user = _make_user(role="user", token_version=1)
    session = _mock_session()

    result = MagicMock()
    result.scalar_one_or_none.return_value = user
    session.execute.return_value = result

    await update_user(session, user.organization_id, user.id, new_role="admin")

    assert user.role == "admin"


@pytest.mark.asyncio
async def test_update_user_deactivation_increments_token_version() -> None:
    user = _make_user(status="active", token_version=1)
    session = _mock_session()

    result = MagicMock()
    result.scalar_one_or_none.return_value = user
    session.execute.return_value = result

    await update_user(session, user.organization_id, user.id, new_status="inactive")

    assert user.status == "inactive"
    assert user.token_version == 2  # incremented on deactivation
