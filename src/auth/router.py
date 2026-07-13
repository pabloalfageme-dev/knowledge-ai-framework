import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth.dependencies import get_current_user, get_token_payload, require_role
from src.auth.models import User
from src.auth.schemas import (
    AuditLogResponse,
    CreateOrganizationRequest,
    CreateServiceAccountRequest,
    CreateUserRequest,
    LoginRequest,
    LogoutRequest,
    OrganizationDetail,
    RefreshRequest,
    ServiceAccountCreated,
    SetupRequest,
    SetupResponse,
    SystemHealth,
    TokenPair,
    UpdateOrganizationRequest,
    UpdateUserRequest,
    UserDetail,
    UserSummary,
)
from src.auth.service import (
    AlreadyInitializedError,
    authenticate_user,
    create_first_org_and_admin,
    create_organization,
    create_service_account,
    create_user,
    deactivate_organization,
    get_audit_log,
    get_system_health,
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
#   Phase 5 (US3): GET/POST /users, PATCH /users/{id},
#                  POST /users/{id}/unlock, POST /service-accounts
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
    token_payload: dict = Depends(get_token_payload),
) -> None:
    jti = token_payload["jti"]
    exp = datetime.fromtimestamp(token_payload["exp"], UTC)
    ip = request.client.host if request.client else "unknown"
    await logout(
        db,
        current_user=current_user,
        raw_refresh_token=body.refresh_token,
        access_jti=jti,
        access_exp=exp,
        ip_address=ip,
    )


# ── Phase 5 (US3) ─────────────────────────────────────────────────────────────

@router.get("/users", response_model=list[UserSummary])
async def list_users_endpoint(
    status_filter: str | None = Query(default=None, alias="status"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
) -> list[User]:
    return await list_users(db, org_id=current_user.organization_id, status_filter=status_filter)


@router.post("/users", status_code=status.HTTP_201_CREATED, response_model=UserDetail)
async def create_user_endpoint(
    body: CreateUserRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
) -> User:
    return await create_user(
        db,
        org_id=current_user.organization_id,
        email=body.email,
        password=body.password,
        role=body.role,
    )


@router.patch("/users/{user_id}", response_model=UserDetail)
async def update_user_endpoint(
    user_id: uuid.UUID,
    body: UpdateUserRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
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
    current_user: User = Depends(require_role("admin")),
) -> None:
    await unlock_user(db, org_id=current_user.organization_id, user_id=user_id)


@router.post(
    "/service-accounts", status_code=status.HTTP_201_CREATED, response_model=ServiceAccountCreated
)
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


# ── Phase 6 (US4) ─────────────────────────────────────────────────────────────

@router.get("/audit", response_model=AuditLogResponse)
async def list_audit_log(
    event_type: str | None = Query(default=None),
    user_id: uuid.UUID | None = Query(default=None),
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = Query(default=None),
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
) -> AuditLogResponse:
    items, total = await get_audit_log(
        db,
        org_id=current_user.organization_id,
        event_type=event_type,
        user_id=user_id,
        from_dt=from_,
        to_dt=to,
        limit=limit,
        offset=offset,
    )
    return AuditLogResponse(items=items, total=total)


# ── Phase 7 (US5) ─────────────────────────────────────────────────────────────

@router.post(
    "/organizations", status_code=status.HTTP_201_CREATED, response_model=OrganizationDetail
)
async def create_organization_endpoint(
    body: CreateOrganizationRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("super_admin")),
) -> OrganizationDetail:
    org = await create_organization(db, name=body.name)
    return OrganizationDetail.model_validate(org)


@router.patch("/organizations/{org_id}", response_model=OrganizationDetail)
async def update_organization_endpoint(
    org_id: uuid.UUID,
    body: UpdateOrganizationRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("super_admin")),
) -> OrganizationDetail:
    org = await deactivate_organization(db, org_id=org_id)
    return OrganizationDetail.model_validate(org)


@router.get("/system/health", response_model=SystemHealth)
async def system_health_endpoint(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("super_admin")),
) -> SystemHealth:
    counts = await get_system_health(db)
    return SystemHealth(**counts)
