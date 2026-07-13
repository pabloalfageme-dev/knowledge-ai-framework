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
from src.auth.models import AuditLogEntry, Organization, RefreshToken, RevokedToken, User
from src.auth.schemas import TokenPair
from src.auth.security import (
    create_access_token,
    generate_api_key,
    hash_password,
    hash_refresh_token,
    verify_password,
)
from src.core.database import set_admin_context, set_app_context, set_rls_context

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
    await session.flush()  # populate org.id before setting RLS context

    # RLS WITH CHECK on users requires app.current_org_id = organization_id.
    # Set it to the new org's id before the user INSERT so the check passes under kn_app.
    await set_rls_context(session, org.id)

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
    # Email lookup is cross-org by design; kn_admin bypasses RLS for this query.
    # All subsequent writes in this function (failed_login_count, audit log,
    # refresh token) run under kn_admin too — legitimate since they target the
    # user being authenticated and don't cross tenant boundaries.
    await set_admin_context(session)
    result = await session.execute(
        select(User, Organization.status.label("org_status"))
        .join(Organization, User.organization_id == Organization.id, isouter=True)
        .where(User.email == email)
    )
    row = result.one_or_none()

    if row is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    user, org_status = row

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
    if user.organization_id is not None and org_status != "active":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Organization is inactive"
        )

    # Revert from kn_admin back to kn_app so remaining writes run under RLS.
    # super_admin has organization_id=None: no org context to set, stay as kn_admin
    # so audit and token writes bypass the policy (audit_log.organization_id IS NULL).
    if user.organization_id is not None:
        await set_app_context(session)
        await set_rls_context(session, user.organization_id)

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
    # refresh_tokens has RLS; org context is unknown at this point, so elevate
    # to kn_admin for the initial lookup. All subsequent ops in this function
    # are for the token owner and don't cross tenant boundaries.
    await set_admin_context(session)
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

    # LEFT JOIN: super_admin has organization_id=None; INNER JOIN would drop that row.
    user_result = await session.execute(
        select(User, Organization.status.label("org_status"))
        .join(Organization, User.organization_id == Organization.id, isouter=True)
        .where(User.id == rt.user_id)
        .where(User.status == "active")
    )
    row = user_result.one_or_none()

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User or organization is inactive"
        )
    user, org_status = row
    if user.organization_id is not None and org_status != "active":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User or organization is inactive"
        )

    # Revert from kn_admin back to kn_app so audit and token writes run under RLS.
    # super_admin (org=None): no org context to set, stay as kn_admin.
    if user.organization_id is not None:
        await set_app_context(session)
        await set_rls_context(session, user.organization_id)

    await write_audit_entry(
        session, "TOKEN_REFRESH", ip_address, user_id=user.id, org_id=user.organization_id
    )
    return await _issue_token_pair(session, user)


async def logout(
    session: AsyncSession,
    current_user: User,
    raw_refresh_token: uuid.UUID,
    access_jti: str,
    access_exp: datetime,
    ip_address: str,
) -> None:
    # super_admin has organization_id=None: app.current_org_id is unset, so kn_app
    # cannot find their refresh tokens via the RLS policy. Escalate to kn_admin.
    if current_user.organization_id is None:
        await set_admin_context(session)
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

    # Blocklist the access JTI so it is rejected within REVOCATION_CACHE_TTL_SECONDS
    revoked = RevokedToken(jti=access_jti, user_id=current_user.id, expires_at=access_exp)
    session.add(revoked)
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


# ── Phase 6 (US4) ─────────────────────────────────────────────────────────────

async def get_audit_log(
    session: AsyncSession,
    org_id: uuid.UUID,
    event_type: str | None = None,
    user_id: uuid.UUID | None = None,
    from_dt: datetime | None = None,
    to_dt: datetime | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[AuditLogEntry], int]:
    """Return paginated audit entries for org_id, plus the unfiltered total count.

    RLS also enforces org scoping when running under kn_app; the WHERE clause
    is the application-layer guard.
    """
    base = select(AuditLogEntry).where(AuditLogEntry.organization_id == org_id)

    if event_type is not None:
        base = base.where(AuditLogEntry.event_type == event_type)
    if user_id is not None:
        base = base.where(AuditLogEntry.user_id == user_id)
    if from_dt is not None:
        base = base.where(AuditLogEntry.occurred_at >= from_dt)
    if to_dt is not None:
        base = base.where(AuditLogEntry.occurred_at <= to_dt)

    count_result = await session.execute(
        select(func.count()).select_from(base.subquery())
    )
    total = count_result.scalar_one()

    items_result = await session.execute(
        base.order_by(AuditLogEntry.occurred_at.desc()).limit(limit).offset(offset)
    )
    items = list(items_result.scalars().all())
    return items, total


# ── Phase 7 (US5) ─────────────────────────────────────────────────────────────

async def create_organization(
    session: AsyncSession,
    name: str,
) -> Organization:
    """Create a new organization. Raises 409 on duplicate name."""
    from sqlalchemy.exc import IntegrityError

    from src.core.database import set_admin_context

    await set_admin_context(session)
    org = Organization(name=name)
    session.add(org)
    try:
        await session.flush()
    except IntegrityError as err:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Organization name already exists"
        ) from err
    return org


async def deactivate_organization(
    session: AsyncSession,
    org_id: uuid.UUID,
) -> Organization:
    """Set an organization's status to inactive. Raises 404 if not found."""
    from src.core.database import set_admin_context

    await set_admin_context(session)
    result = await session.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
    org.status = "inactive"
    await session.flush()
    return org


async def get_system_health(session: AsyncSession) -> dict:
    """Return aggregate org/user counts with no user-identifiable data."""
    from src.core.database import set_admin_context

    await set_admin_context(session)

    org_counts = await session.execute(
        select(
            func.count().label("total"),
            func.count(Organization.id).filter(Organization.status == "active").label("active"),
        )
    )
    org_row = org_counts.one()

    user_count_result = await session.execute(
        select(func.count()).where(User.status == "active")
    )
    active_user_count = user_count_result.scalar_one()

    return {
        "organization_count": org_row.total,
        "active_organization_count": org_row.active,
        "active_user_count": active_user_count,
    }
