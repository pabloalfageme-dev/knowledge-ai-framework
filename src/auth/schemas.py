import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr

# ── Setup ────────────────────────────────────────────────────────────────────

class SetupRequest(BaseModel):
    organization_name: str
    admin_email: EmailStr
    admin_password: str


class SetupResponse(BaseModel):
    organization_id: uuid.UUID
    organization_name: str
    admin_user_id: uuid.UUID


# ── Auth ─────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: uuid.UUID


class LogoutRequest(BaseModel):
    refresh_token: uuid.UUID


class TokenPair(BaseModel):
    access_token: str
    refresh_token: uuid.UUID
    token_type: str = "bearer"
    expires_in: int


# ── Users ────────────────────────────────────────────────────────────────────

class CreateUserRequest(BaseModel):
    email: EmailStr
    password: str
    role: str  # "admin" | "user"


class UpdateUserRequest(BaseModel):
    status: str | None = None   # "active" | "inactive"
    role: str | None = None     # "admin" | "user"


class UserSummary(BaseModel):
    id: uuid.UUID
    email: str
    role: str
    status: str
    credential_type: str
    locked_until: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class UserDetail(UserSummary):
    organization_id: uuid.UUID | None


# ── Service Accounts ─────────────────────────────────────────────────────────

class CreateServiceAccountRequest(BaseModel):
    email: EmailStr
    role: str  # "admin" | "user"


class ServiceAccountCreated(BaseModel):
    id: uuid.UUID
    email: str
    role: str
    api_key: str  # returned exactly once; not stored in plain text
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Audit Log ────────────────────────────────────────────────────────────────

class AuditEntry(BaseModel):
    id: uuid.UUID
    occurred_at: datetime
    user_id: uuid.UUID | None
    event_type: str
    ip_address: str

    model_config = {"from_attributes": True}


class AuditLogResponse(BaseModel):
    items: list[AuditEntry]
    total: int


# ── Organizations ─────────────────────────────────────────────────────────────

class CreateOrganizationRequest(BaseModel):
    name: str


class UpdateOrganizationRequest(BaseModel):
    status: str  # "active" | "inactive"


class OrganizationDetail(BaseModel):
    id: uuid.UUID
    name: str
    status: str
    created_at: datetime

    model_config = {"from_attributes": True}


# ── System ────────────────────────────────────────────────────────────────────

class SystemHealth(BaseModel):
    organization_count: int
    active_organization_count: int
    active_user_count: int


# ── Errors ────────────────────────────────────────────────────────────────────

class ErrorResponse(BaseModel):
    detail: str
