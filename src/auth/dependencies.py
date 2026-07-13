"""FastAPI dependencies — Phase 4 (US1)."""
import logging
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth.models import Organization, User
from src.auth.security import decode_access_token
from src.core.database import get_db, set_admin_context, set_app_context, set_rls_context

_logger = logging.getLogger(__name__)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

_CREDENTIALS_EXCEPTION = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: AsyncSession = Depends(get_db),
) -> User:
    try:
        payload = decode_access_token(token)
    except jwt.PyJWTError:
        raise _CREDENTIALS_EXCEPTION

    user_id = payload.get("sub")
    token_version = payload.get("tv")
    if user_id is None:
        raise _CREDENTIALS_EXCEPTION

    # kn_admin bypasses RLS so we can look up any user (including super_admin with org=None)
    # before the org context is known. set_app_context reverts to kn_app afterwards so
    # the request handler runs under the tenant_isolation RLS policy.
    await set_admin_context(db)
    result = await db.execute(
        select(User, Organization.status.label("org_status"))
        # LEFT JOIN: super_admin users have organization_id=None and must not be excluded
        .join(Organization, User.organization_id == Organization.id, isouter=True)
        .where(User.id == user_id)
    )
    row = result.one_or_none()
    if row is None:
        raise _CREDENTIALS_EXCEPTION

    user, org_status = row

    if user.status != "active":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User is inactive"
        )
    # org_status is None for super_admin (no org) — only check when an org exists
    if user.organization_id is not None and org_status != "active":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Organization is inactive"
        )
    if user.token_version != token_version:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has been revoked"
        )

    await set_rls_context(db, user.organization_id)
    # Revert to kn_app so request handlers are subject to the RLS policy
    await set_app_context(db)
    return user


def require_role(*roles: str):
    async def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return current_user

    return role_checker