import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth.dependencies import get_current_user, require_role
from src.auth.models import User
from src.auth.schemas import (
    CreateServiceAccountRequest,
    CreateUserRequest,
    LoginRequest,
    LogoutRequest,
    RefreshRequest,
    ServiceAccountCreated,
    SetupRequest,
    SetupResponse,
    TokenPair,
    UpdateUserRequest,
    UserDetail,
    UserSummary,
)
from src.auth.service import (
    AlreadyInitializedError,
    authenticate_user,
    create_first_org_and_admin,
    create_service_account,
    create_user,
    list_users,
    logout,
    refresh_tokens,
    unlock_user,
    update_user,
)
from src.core.database import get_db

router = APIRouter()

# Endpoints are added by each user-story phase:
#   Phase 3 (US2): POST /setup
#   Phase 4 (US1): GET /health, POST /auth/login, POST /auth/refresh, POST /auth/logout
#   Phase 5 (US3): GET/POST /users, PATCH /users/{id}, POST /users/{id}/unlock, POST /service-accounts
#   Phase 6 (US4): GET /audit
#   Phase 7 (US5): POST /organizations, PATCH /organizations/{id}, GET /system/health


# ── Phase 3 (US2) ────────────────────────────────────────────────────────────

@router.post("/setup", status_code=status.HTTP_201_CREATED, response_model=SetupResponse)
async def bootstrap_setup(
    body: SetupRequest,
    db: AsyncSession = Depends(get_db),
) -> SetupResponse:
    """One-time bootstrap: create the first organization and admin user."""
    try:
        org_id, user_id = await create_first_org_and_admin(
            db,
            org_name=body.organization_name,
            admin_email=body.admin_email,
            admin_password=body.admin_password,
        )
    except AlreadyInitializedError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    return SetupResponse(
        organization_id=org_id,
        organization_name=body.organization_name,
        admin_user_id=user_id,
    )


# ── Phase 4 (US1) ─────────────────────────────────────────────────────────────

@router.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@router.post("/auth/login", response_model=TokenPair)
async def login(
    body: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> TokenPair:
    ip = request.client.host if request.client else "unknown"
    return await authenticate_user(db, email=body.email, password=body.password, ip_address=ip)


@router.post("/auth/refresh", response_model=TokenPair)
async def refresh(
    body: RefreshRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> TokenPair:
    ip = request.client.host if request.client else "unknown"
    return await refresh_tokens(db, raw_refresh_token=body.refresh_token, ip_address=ip)


@router.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout_endpoint(
    body: LogoutRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    ip = request.client.host if request.client else "unknown"
    await logout(db, current_user=current_user, raw_refresh_token=body.refresh_token, ip_address=ip)


# ── Phase 5 (US3) ─────────────────────────────────────────────────────────────

@router.get("/users", response_model=list[UserSummary])
async def list_users_endpoint(
    status_filter: str | None = Query(default=None, alias="status"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("admin", "super_admin")),
) -> list[User]:
    return await list_users(db, org_id=current_user.organization_id, status_filter=status_filter)


@router.post("/users", status_code=status.HTTP_201_CREATED, response_model=UserDetail)
async def create_user_endpoint(
    body: CreateUserRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("admin", "super_admin")),
) -> User:
    return await create_user(
        db, org_id=current_user.organization_id, email=body.email, password=body.password, role=body.role
    )


@router.patch("/users/{user_id}", response_model=UserDetail)
async def update_user_endpoint(
    user_id: uuid.UUID,
    body: UpdateUserRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("admin", "super_admin")),
) -> User:
    return await update_user(
        db,
        org_id=current_user.organization_id,
        user_id=user_id,
        new_status=body.status,
        new_role=body.role,
    )


@router.post("/users/{user_id}/unlock", status_code=status.HTTP_204_NO_CONTENT)
async def unlock_user_endpoint(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("admin", "super_admin")),
) -> None:
    await unlock_user(db, org_id=current_user.organization_id, user_id=user_id)


@router.post("/service-accounts", status_code=status.HTTP_201_CREATED, response_model=ServiceAccountCreated)
async def create_service_account_endpoint(
    body: CreateServiceAccountRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
) -> ServiceAccountCreated:
    sa_user, raw_key = await create_service_account(
        db, org_id=current_user.organization_id, email=body.email, role=body.role
    )
    return ServiceAccountCreated(
        id=sa_user.id,
        email=sa_user.email,
        role=sa_user.role,
        api_key=raw_key,
        created_at=sa_user.created_at,
    )