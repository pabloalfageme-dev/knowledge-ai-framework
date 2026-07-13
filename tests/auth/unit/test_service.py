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


# ── create_first_org_and_admin ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_first_org_and_admin_raises_when_already_initialized() -> None:
    from src.auth.service import AlreadyInitializedError, create_first_org_and_admin

    session = _mock_session()
    count_result = MagicMock()
    count_result.scalar_one.return_value = 1
    session.execute.return_value = count_result

    with pytest.raises(AlreadyInitializedError):
        await create_first_org_and_admin(session, "Acme", "admin@acme.com", "S3cr3t!")


@pytest.mark.asyncio
async def test_create_first_org_and_admin_adds_org_and_user() -> None:
    from src.auth.service import create_first_org_and_admin

    session = _mock_session()
    count_result = MagicMock()
    count_result.scalar_one.return_value = 0
    session.execute.return_value = count_result

    with patch("src.auth.service.set_rls_context", new=AsyncMock()):
        await create_first_org_and_admin(session, "Acme", "admin@acme.com", "S3cr3t!")

    assert session.add.call_count == 2  # org + user
    assert session.flush.call_count == 2


# ── authenticate_user: missing branches ──────────────────────────────────────

@pytest.mark.asyncio
async def test_authenticate_user_user_not_found_returns_401() -> None:
    session = _mock_session()
    mock_row = MagicMock()
    mock_row.one_or_none.return_value = None
    session.execute.return_value = mock_row

    with (
        patch("src.auth.service.set_admin_context", new=AsyncMock()),
        patch("src.auth.service.write_audit_entry", new=AsyncMock()),
    ):
        with pytest.raises(HTTPException) as exc_info:
            await authenticate_user(session, "ghost@example.com", "any", "127.0.0.1")

    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_authenticate_user_inactive_user_returns_401() -> None:
    user = _make_user(status="inactive")
    session = _mock_session()
    mock_row = MagicMock()
    mock_row.one_or_none.return_value = (user, "active")
    session.execute.return_value = mock_row

    with (
        patch("src.auth.service.set_admin_context", new=AsyncMock()),
        patch("src.auth.service.verify_password", return_value=True),
        patch("src.auth.service.write_audit_entry", new=AsyncMock()),
    ):
        with pytest.raises(HTTPException) as exc_info:
            await authenticate_user(session, "user@example.com", "correct", "127.0.0.1")

    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_authenticate_user_inactive_org_returns_401() -> None:
    user = _make_user(status="active")
    session = _mock_session()
    mock_row = MagicMock()
    mock_row.one_or_none.return_value = (user, "inactive")
    session.execute.return_value = mock_row

    with (
        patch("src.auth.service.set_admin_context", new=AsyncMock()),
        patch("src.auth.service.verify_password", return_value=True),
        patch("src.auth.service.write_audit_entry", new=AsyncMock()),
    ):
        with pytest.raises(HTTPException) as exc_info:
            await authenticate_user(session, "user@example.com", "correct", "127.0.0.1")

    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_authenticate_user_success_returns_token_pair() -> None:
    from src.auth.schemas import TokenPair

    user = _make_user(status="active")
    session = _mock_session()
    mock_row = MagicMock()
    mock_row.one_or_none.return_value = (user, "active")
    session.execute.return_value = mock_row

    with (
        patch("src.auth.service.set_admin_context", new=AsyncMock()),
        patch("src.auth.service.verify_password", return_value=True),
        patch("src.auth.service.write_audit_entry", new=AsyncMock()),
    ):
        result = await authenticate_user(session, "user@example.com", "correct", "127.0.0.1")

    assert isinstance(result, TokenPair)
    assert user.failed_login_count == 0
    assert user.locked_until is None


# ── refresh_tokens: missing branches ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_refresh_tokens_not_found_returns_401() -> None:
    session = _mock_session()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    session.execute.return_value = mock_result

    with (
        patch("src.auth.service.set_admin_context", new=AsyncMock()),
        patch("src.auth.service.hash_refresh_token", return_value="hash"),
    ):
        with pytest.raises(HTTPException) as exc_info:
            await refresh_tokens(session, uuid.uuid4(), "127.0.0.1")

    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_refresh_tokens_expired_returns_401() -> None:
    now = datetime.now(UTC)
    rt = MagicMock(spec=RefreshToken)
    rt.used_at = None
    rt.expires_at = now - timedelta(minutes=1)
    rt.family_id = uuid.uuid4()

    session = _mock_session()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = rt
    session.execute.return_value = mock_result

    with (
        patch("src.auth.service.set_admin_context", new=AsyncMock()),
        patch("src.auth.service.hash_refresh_token", return_value="hash"),
    ):
        with pytest.raises(HTTPException) as exc_info:
            await refresh_tokens(session, uuid.uuid4(), "127.0.0.1")

    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_refresh_tokens_success_returns_token_pair() -> None:
    from src.auth.schemas import TokenPair

    now = datetime.now(UTC)
    rt = MagicMock(spec=RefreshToken)
    rt.used_at = None
    rt.expires_at = now + timedelta(days=7)
    rt.family_id = uuid.uuid4()
    rt.user_id = uuid.uuid4()

    user = _make_user(status="active")
    session = _mock_session()

    rt_result = MagicMock()
    rt_result.scalar_one_or_none.return_value = rt
    user_result = MagicMock()
    user_result.one_or_none.return_value = (user, "active")
    session.execute.side_effect = [rt_result, user_result]

    with (
        patch("src.auth.service.set_admin_context", new=AsyncMock()),
        patch("src.auth.service.hash_refresh_token", return_value="hash"),
        patch("src.auth.service.write_audit_entry", new=AsyncMock()),
    ):
        result = await refresh_tokens(session, uuid.uuid4(), "127.0.0.1")

    assert isinstance(result, TokenPair)


# ── logout: super_admin branch ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_logout_super_admin_calls_set_admin_context() -> None:
    user = _make_user(organization_id=None)
    session = _mock_session()
    rt_result = MagicMock()
    rt_result.scalar_one_or_none.return_value = None
    session.execute.return_value = rt_result

    jti = str(uuid.uuid4())
    exp = datetime.now(UTC) + timedelta(minutes=15)

    with (
        patch("src.auth.service.set_admin_context", new=AsyncMock()) as mock_admin_ctx,
        patch("src.auth.service.write_audit_entry", new=AsyncMock()),
    ):
        await logout(session, user, uuid.uuid4(), jti, exp, "127.0.0.1")

    mock_admin_ctx.assert_called_once()


# ── list_users ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_users_returns_all_org_users() -> None:
    from src.auth.service import list_users

    org_id = uuid.uuid4()
    users = [_make_user(organization_id=org_id), _make_user(organization_id=org_id)]
    session = _mock_session()
    result = MagicMock()
    result.scalars.return_value.all.return_value = users
    session.execute.return_value = result

    returned = await list_users(session, org_id)

    assert returned == users


@pytest.mark.asyncio
async def test_list_users_with_status_filter_passes_query() -> None:
    from src.auth.service import list_users

    org_id = uuid.uuid4()
    session = _mock_session()
    result = MagicMock()
    result.scalars.return_value.all.return_value = []
    session.execute.return_value = result

    returned = await list_users(session, org_id, status_filter="active")

    assert returned == []
    session.execute.assert_called_once()


# ── create_user ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_user_returns_new_user() -> None:
    from src.auth.service import create_user

    org_id = uuid.uuid4()
    session = _mock_session()
    no_user = MagicMock()
    no_user.scalar_one_or_none.return_value = None
    session.execute.return_value = no_user

    user = await create_user(session, org_id, "new@example.com", "S3cr3t!", "user")

    session.add.assert_called_once()
    session.flush.assert_called_once()
    assert user.email == "new@example.com"
    assert user.credential_type == "password"


@pytest.mark.asyncio
async def test_create_user_duplicate_email_raises_409() -> None:
    from src.auth.service import create_user

    org_id = uuid.uuid4()
    session = _mock_session()
    result = MagicMock()
    result.scalar_one_or_none.return_value = _make_user()
    session.execute.return_value = result

    with pytest.raises(HTTPException) as exc_info:
        await create_user(session, org_id, "taken@example.com", "pass", "user")

    assert exc_info.value.status_code == 409


# ── update_user: 404 branch ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_update_user_not_found_raises_404() -> None:
    session = _mock_session()
    result = MagicMock()
    result.scalar_one_or_none.return_value = None
    session.execute.return_value = result

    with pytest.raises(HTTPException) as exc_info:
        await update_user(session, uuid.uuid4(), uuid.uuid4(), new_status="inactive")

    assert exc_info.value.status_code == 404


# ── unlock_user ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_unlock_user_resets_lock_fields() -> None:
    from src.auth.service import unlock_user

    user = _make_user(failed_login_count=5, locked_until=datetime.now(UTC) + timedelta(minutes=5))
    session = _mock_session()
    result = MagicMock()
    result.scalar_one_or_none.return_value = user
    session.execute.return_value = result

    await unlock_user(session, user.organization_id, user.id)

    assert user.failed_login_count == 0
    assert user.locked_until is None
    session.flush.assert_called_once()


@pytest.mark.asyncio
async def test_unlock_user_not_found_raises_404() -> None:
    from src.auth.service import unlock_user

    session = _mock_session()
    result = MagicMock()
    result.scalar_one_or_none.return_value = None
    session.execute.return_value = result

    with pytest.raises(HTTPException) as exc_info:
        await unlock_user(session, uuid.uuid4(), uuid.uuid4())

    assert exc_info.value.status_code == 404


# ── create_service_account ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_service_account_returns_user_and_api_key() -> None:
    from src.auth.service import create_service_account

    org_id = uuid.uuid4()
    session = _mock_session()
    no_user = MagicMock()
    no_user.scalar_one_or_none.return_value = None
    session.execute.return_value = no_user

    user, raw_key = await create_service_account(session, org_id, "sa@example.com", "user")

    assert user.credential_type == "api_key"
    assert len(raw_key) == 36  # UUID string
    session.add.assert_called_once()


@pytest.mark.asyncio
async def test_create_service_account_duplicate_email_raises_409() -> None:
    from src.auth.service import create_service_account

    session = _mock_session()
    result = MagicMock()
    result.scalar_one_or_none.return_value = _make_user()
    session.execute.return_value = result

    with pytest.raises(HTTPException) as exc_info:
        await create_service_account(session, uuid.uuid4(), "taken@example.com", "user")

    assert exc_info.value.status_code == 409


# ── get_audit_log ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_audit_log_returns_items_and_total() -> None:
    from src.auth.service import get_audit_log

    org_id = uuid.uuid4()
    session = _mock_session()
    count_result = MagicMock()
    count_result.scalar_one.return_value = 3
    items_result = MagicMock()
    items_result.scalars.return_value.all.return_value = ["e1", "e2", "e3"]
    session.execute.side_effect = [count_result, items_result]

    items, total = await get_audit_log(session, org_id)

    assert total == 3
    assert len(items) == 3


@pytest.mark.asyncio
async def test_get_audit_log_with_all_optional_filters() -> None:
    from src.auth.service import get_audit_log

    org_id = uuid.uuid4()
    now = datetime.now(UTC)
    session = _mock_session()
    count_result = MagicMock()
    count_result.scalar_one.return_value = 0
    items_result = MagicMock()
    items_result.scalars.return_value.all.return_value = []
    session.execute.side_effect = [count_result, items_result]

    items, total = await get_audit_log(
        session,
        org_id,
        event_type="LOGIN_FAILURE",
        user_id=uuid.uuid4(),
        from_dt=now - timedelta(hours=1),
        to_dt=now,
    )

    assert total == 0
    assert items == []


# ── create_organization ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_organization_returns_org() -> None:
    from src.auth.service import create_organization

    session = _mock_session()

    with patch("src.core.database.set_admin_context", new=AsyncMock()):
        org = await create_organization(session, "NewCorp")

    assert org.name == "NewCorp"
    session.add.assert_called_once()


@pytest.mark.asyncio
async def test_create_organization_duplicate_name_raises_409() -> None:
    from sqlalchemy.exc import IntegrityError

    from src.auth.service import create_organization

    session = _mock_session()
    session.flush.side_effect = IntegrityError("INSERT", {}, Exception("unique"))

    with (
        patch("src.core.database.set_admin_context", new=AsyncMock()),
    ):
        with pytest.raises(HTTPException) as exc_info:
            await create_organization(session, "Duplicate")

    assert exc_info.value.status_code == 409


# ── deactivate_organization ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_deactivate_organization_sets_status_inactive() -> None:
    from src.auth.service import deactivate_organization

    org = MagicMock()
    org.status = "active"
    session = _mock_session()
    result = MagicMock()
    result.scalar_one_or_none.return_value = org
    session.execute.return_value = result

    with patch("src.core.database.set_admin_context", new=AsyncMock()):
        returned = await deactivate_organization(session, uuid.uuid4())

    assert returned.status == "inactive"


@pytest.mark.asyncio
async def test_deactivate_organization_not_found_raises_404() -> None:
    from src.auth.service import deactivate_organization

    session = _mock_session()
    result = MagicMock()
    result.scalar_one_or_none.return_value = None
    session.execute.return_value = result

    with patch("src.core.database.set_admin_context", new=AsyncMock()):
        with pytest.raises(HTTPException) as exc_info:
            await deactivate_organization(session, uuid.uuid4())

    assert exc_info.value.status_code == 404


# ── get_system_health ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_system_health_returns_aggregate_counts() -> None:
    from src.auth.service import get_system_health

    session = _mock_session()
    org_row = MagicMock()
    org_row.total = 5
    org_row.active = 3
    org_result = MagicMock()
    org_result.one.return_value = org_row

    user_result = MagicMock()
    user_result.scalar_one.return_value = 12
    session.execute.side_effect = [org_result, user_result]

    with patch("src.core.database.set_admin_context", new=AsyncMock()):
        health = await get_system_health(session)

    assert health["organization_count"] == 5
    assert health["active_organization_count"] == 3
    assert health["active_user_count"] == 12
