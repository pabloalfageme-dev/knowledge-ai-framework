"""Auth service layer — business logic implemented phase by phase.

Phase 3 (US2): create_first_org_and_admin
Phase 4 (US1): write_audit_entry, authenticate_user, _issue_token_pair,
               refresh_tokens, logout
Phase 5 (US3): list_users, create_user, update_user, unlock_user,
               create_service_account
Phase 6 (US4): get_audit_log
Phase 7 (US5): create_organization, deactivate_organization, get_system_health
"""
import logging
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException, status
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth.config import auth_settings
from src.auth.models import AuditLogEntry, Organization, RefreshToken, User
from src.auth.schemas import TokenPair
from src.auth.security import (
    create_access_token,
    generate_api_key,
    hash_password,
    hash_refresh_token,
    verify_password,
)

_logger = logging.getLogger(__name__)


class AlreadyInitializedError(Exception):
    pass


# ── Phase 3 (US2) ────────────────────────────────────────────────────────────

async def create_first_org_and_admin(
    session: AsyncSession,
    org_name: str,
    admin_email: str,
    admin_password: str,
) -> tuple[uuid.UUID, uuid.UUID]:
    """Bootstrap the first organization and admin user.

    Raises AlreadyInitializedError if any organization already exists.
    Returns (org_id, user_id).
    """
    count_result = await session.execute(select(func.count()).select_from(Organization))
    if count_result.scalar_one() > 0:
        raise AlreadyInitializedError("System is already initialized.")

    org = Organization(name=org_name)
    session.add(org)
    await session.flush()  # populate org.id

    user = User(
        organization_id=org.id,
        email=admin_email,
        credential_hash=hash_password(admin_password),
        credential_type="password",
        role="admin",
        status="active",
    )
    session.add(user)
    await session.flush()  # populate user.id

    return org.id, user.id


# ── Phase 4 (US1) ─────────────────────────────────────────────────────────────

async def write_audit_entry(
    session: AsyncSession,
    event_type: str,
    ip_address: str,
    user_id: uuid.UUID | None = None,
    org_id: uuid.UUID | None = None,
) -> None:
    """Insert an audit log entry. Non-blocking — logs but does not raise on failure."""
    try:
        entry = AuditLogEntry(
            event_type=event_type,
            ip_address=ip_address,
            user_id=user_id,
            organization_id=org_id,
        )
        session.add(entry)
        await session.flush()
    except Exception:
        _logger.exception("Failed to write audit entry (non-blocking)")


async def _issue_token_pair(session: AsyncSession, user: User) -> TokenPair:
    """Persist a new refresh token and return a JWT access + refresh token pair."""
    family_id = uuid.uuid4()
    raw_refresh = uuid.uuid4()
    token_hash = hash_refresh_token(str(raw_refresh))
    now = datetime.now(UTC)
    expires_at = now + timedelta(days=auth_settings.REFRESH_TOKEN_EXPIRE_DAYS)

    rt = RefreshToken(
        user_id=user.id,
        organization_id=user.organization_id,
        family_id=family_id,
        token_hash=token_hash,
        expires_at=expires_at,
    )
    session.add(rt)
    await session.flush()

    access_token, _ = create_access_token(
        user.id, user.organization_id, user.role, user.token_version
    )
    return TokenPair(
        access_token=access_token,
        refresh_token=raw_refresh,
        expires_in=auth_settings.ACCESS_TOKEN_EXPIRE_SECONDS,
    )


async def authenticate_user(
    session: AsyncSession,
    email: str,
    password: str,
    ip_address: str,
) -> TokenPair:
    result = await session.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    now = datetime.now(UTC)
    if user.locked_until and user.locked_until > now:
        await write_audit_entry(
            session, "LOGIN_FAILURE", ip_address, user_id=user.id, org_id=user.organization_id
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Account temporarily locked"
        )

    password_valid = (
        hash_refresh_token(password) == user.credential_hash
        if user.credential_type == "api_key"
        else verify_password(password, user.credential_hash)
    )
    if not password_valid:
        user.failed_login_count += 1
        if user.failed_login_count >= auth_settings.LOCKOUT_ATTEMPT_THRESHOLD:
            user.locked_until = now + timedelta(minutes=auth_settings.LOCKOUT_DURATION_MINUTES)
        await session.flush()
        await write_audit_entry(
            session, "LOGIN_FAILURE", ip_address, user_id=user.id, org_id=user.organization_id
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if user.status != "active":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Account is not active"
        )

    user.failed_login_count = 0
    user.locked_until = None
    await session.flush()
    await write_audit_entry(
        session, "LOGIN_SUCCESS", ip_address, user_id=user.id, org_id=user.organization_id
    )
    return await _issue_token_pair(session, user)


async def refresh_tokens(
    session: AsyncSession,
    raw_refresh_token: uuid.UUID,
    ip_address: str,
) -> TokenPair:
    token_hash = hash_refresh_token(str(raw_refresh_token))
    result = await session.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    )
    rt = result.scalar_one_or_none()

    if rt is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token"
        )

    now = datetime.now(UTC)

    if rt.used_at is not None:
        # Token reuse detected — revoke entire family
        await session.execute(
            update(RefreshToken)
            .where(RefreshToken.family_id == rt.family_id)
            .values(used_at=now)
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token reuse detected"
        )

    if rt.expires_at < now:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired"
        )

    rt.used_at = now
    await session.flush()

    user_result = await session.execute(
        select(User)
        .join(Organization, User.organization_id == Organization.id)
        .where(User.id == rt.user_id)
        .where(User.status == "active")
        .where(Organization.status == "active")
    )
    user = user_result.scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User or organization is inactive"
        )

    await write_audit_entry(
        session, "TOKEN_REFRESH", ip_address, user_id=user.id, org_id=user.organization_id
    )
    return await _issue_token_pair(session, user)


async def logout(
    session: AsyncSession,
    current_user: User,
    raw_refresh_token: uuid.UUID,
    ip_address: str,
) -> None:
    token_hash = hash_refresh_token(str(raw_refresh_token))
    result = await session.execute(
        select(RefreshToken)
        .where(RefreshToken.token_hash == token_hash)
        .where(RefreshToken.user_id == current_user.id)
    )
    rt = result.scalar_one_or_none()
    if rt is not None:
        rt.used_at = datetime.now(UTC)
        await session.flush()
    await write_audit_entry(
        session,
        "LOGOUT",
        ip_address,
        user_id=current_user.id,
        org_id=current_user.organization_id,
    )


# ── Phase 5 (US3) ─────────────────────────────────────────────────────────────

async def list_users(
    session: AsyncSession,
    org_id: uuid.UUID,
    status_filter: str | None = None,
) -> list[User]:
    stmt = select(User).where(User.organization_id == org_id)
    if status_filter:
        stmt = stmt.where(User.status == status_filter)
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def create_user(
    session: AsyncSession,
    org_id: uuid.UUID,
    email: str,
    password: str,
    role: str,
) -> User:
    existing = await session.execute(select(User).where(User.email == email))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already in use")

    user = User(
        organization_id=org_id,
        email=email,
        credential_hash=hash_password(password),
        credential_type="password",
        role=role,
        status="active",
    )
    session.add(user)
    await session.flush()
    return user


async def update_user(
    session: AsyncSession,
    org_id: uuid.UUID,
    user_id: uuid.UUID,
    new_status: str | None = None,
    new_role: str | None = None,
) -> User:
    result = await session.execute(
        select(User).where(User.id == user_id, User.organization_id == org_id)
    )
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if new_status is not None:
        if new_status == "inactive" and user.status == "active":
            user.token_version += 1  # invalidate all active access tokens immediately
        user.status = new_status

    if new_role is not None:
        user.role = new_role

    await session.flush()
    return user


async def unlock_user(
    session: AsyncSession,
    org_id: uuid.UUID,
    user_id: uuid.UUID,
) -> None:
    result = await session.execute(
        select(User).where(User.id == user_id, User.organization_id == org_id)
    )
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user.failed_login_count = 0
    user.locked_until = None
    await session.flush()


async def create_service_account(
    session: AsyncSession,
    org_id: uuid.UUID,
    email: str,
    role: str,
) -> tuple[User, str]:
    """Create a service account. Returns (user, raw_api_key) — key returned once only."""
    existing = await session.execute(select(User).where(User.email == email))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already in use")

    raw_api_key, key_hash = generate_api_key()

    user = User(
        organization_id=org_id,
        email=email,
        credential_hash=key_hash,
        credential_type="api_key",
        role=role,
        status="active",
    )
    session.add(user)
    await session.flush()
    return user, raw_api_key