# Auth Module

Multi-tenant authentication and authorization for KnowledgeAI.

## Purpose

This module is the prerequisite gate for the entire framework. It provides:

- **JWT-based authentication** — HS256 access tokens (short-lived) + rotating refresh tokens
  with theft detection via family-based revocation
- **Multi-tenancy** — strict organization-level data isolation enforced at both the application
  layer and the PostgreSQL database layer via Row-Level Security (RLS)
- **RBAC** — three roles: `user`, `admin`, `super_admin`; enforced on every endpoint via the
  `require_role` dependency
- **Account security** — configurable lockout after N consecutive failed logins; immediate
  deactivation effect on new logins; existing tokens invalidated within one cache TTL window
- **Service accounts** — API key credentials (SHA-256 stored, single reveal at creation)
- **Audit log** — every auth event (login, logout, refresh, lockout) recorded with timestamp,
  user id, org id, and IP address; writes are non-blocking so a failed audit never breaks auth

## Inputs

| Source | Shape | Description |
|--------|-------|-------------|
| `POST /setup` | `SetupRequest` | Bootstrap first organization and admin (no auth required) |
| `POST /auth/login` | `LoginRequest` — email + password | Password or API-key authentication |
| `POST /auth/refresh` | `RefreshRequest` — refresh token UUID | Rotate token pair |
| `POST /auth/logout` | `LogoutRequest` — refresh token UUID; `Authorization: Bearer` header | Revoke session |
| `GET /users` | `Authorization: Bearer` | List users in caller's org |
| `POST /users` | `CreateUserRequest` + `Authorization: Bearer` | Create user in caller's org |
| `PATCH /users/{id}` | `UpdateUserRequest` + `Authorization: Bearer` | Update status or role |
| `POST /users/{id}/unlock` | `Authorization: Bearer` | Clear lockout on a user |
| `POST /service-accounts` | `CreateServiceAccountRequest` + `Authorization: Bearer` | Create API-key credential user |
| `GET /audit` | Query params + `Authorization: Bearer` | Audit log with optional filters |
| `POST /organizations` | `CreateOrganizationRequest` + `Authorization: Bearer` (super_admin) | Create org |
| `PATCH /organizations/{id}` | `UpdateOrganizationRequest` + `Authorization: Bearer` (super_admin) | Deactivate org |
| `GET /system/health` | `Authorization: Bearer` (super_admin) | Aggregate system metrics |
| `GET /health` | — | Liveness check (no auth) |

## Outputs

| Endpoint | Success response | Error responses |
|----------|-----------------|-----------------|
| `POST /setup` | `201 SetupResponse` | `409` already initialized |
| `POST /auth/login` | `200 TokenPair` | `401` invalid credentials / locked |
| `POST /auth/refresh` | `200 TokenPair` | `401` token expired / used / revoked |
| `POST /auth/logout` | `204` | `401` missing / invalid token |
| `GET /users` | `200 list[UserSummary]` | `401` / `403` wrong role |
| `POST /users` | `201 UserDetail` | `401` / `403` / `409` duplicate email |
| `PATCH /users/{id}` | `200 UserDetail` | `401` / `403` / `404` cross-org |
| `POST /users/{id}/unlock` | `200 UserDetail` | `401` / `403` / `404` cross-org |
| `POST /service-accounts` | `201 ServiceAccountCreated` (api_key shown once) | `401` / `403` / `409` |
| `GET /audit` | `200 AuditLogResponse` | `401` / `403` |
| `POST /organizations` | `201 OrganizationDetail` | `401` / `403` / `409` duplicate name |
| `PATCH /organizations/{id}` | `200 OrganizationDetail` | `401` / `403` / `404` |
| `GET /system/health` | `200 SystemHealth` | `401` / `403` |
| `GET /health` | `200 {"status":"ok","version":"1.0.0"}` | — |

Side-effect outputs (written regardless of response):
- `AuditLogEntry` rows in PostgreSQL (non-blocking — auth completes even if audit INSERT fails)
- `RefreshToken` rows on login and refresh
- `RevokedToken` rows on logout

## Configuration

All settings are read from environment variables at startup via `pydantic-settings`.

| Variable | Type | Default | Required | Description |
|---|---|---|---|---|
| `DATABASE_URL` | str | — | Yes | asyncpg DSN: `postgresql+asyncpg://user:pass@host/db` |
| `JWT_SECRET` | str | — | Yes | HS256 signing key (≥ 32 bytes recommended) |
| `ACCESS_TOKEN_EXPIRE_SECONDS` | int | 900 | No | Access token lifetime (15 min) |
| `REFRESH_TOKEN_EXPIRE_DAYS` | int | 7 | No | Refresh token lifetime in days |
| `LOCKOUT_ATTEMPT_THRESHOLD` | int | 5 | No | Failed logins before account lockout |
| `LOCKOUT_DURATION_MINUTES` | int | 15 | No | How long the lockout lasts |
| `REVOCATION_CACHE_TTL_SECONDS` | int | 30 | No | In-process JTI cache TTL; max delay before deactivated token is rejected |
| `APP_ENV` | str | development | No | Runtime environment label (`development` / `production`) |

Generate a secure JWT secret:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Copy `.env.example` to `.env` and fill in at minimum `DATABASE_URL` and `JWT_SECRET`.

## Architecture

```
src/auth/
  config.py        # AuthSettings — pydantic-settings env var loading
  models.py        # SQLAlchemy ORM: Organization, User, AuditLogEntry, RefreshToken, RevokedToken
  schemas.py       # Pydantic v2 request/response models
  security.py      # JWT encode/decode, bcrypt, SHA-256 helpers, API key generation
  service.py       # Business logic (no HTTP concern)
  dependencies.py  # FastAPI deps: get_current_user, require_role
  router.py        # HTTP endpoints mounted at /
```

Database roles:

| Role | BYPASSRLS | Purpose |
|---|---|---|
| `kn_app` | No | Tenant-scoped operations (RLS enforced) |
| `kn_admin` | Yes | Cross-org: login resolution, refresh, super-admin endpoints |

`get_current_user` escalates to `kn_admin` to resolve any user (including `super_admin` with
`organization_id=NULL`), then reverts to `kn_app` after setting `SET LOCAL app.current_org_id`.

## Docker

```bash
docker compose up -d db
docker compose run --rm app alembic upgrade head
docker compose up app
```

## Quick start (curl)

```bash
BASE=http://localhost:8000

# 1. Bootstrap first org + admin
curl -sX POST $BASE/setup \
  -H 'Content-Type: application/json' \
  -d '{"organization_name":"Acme","admin_email":"admin@acme.example","admin_password":"S3cr3t!Pw"}'

# 2. Login — capture tokens
PAIR=$(curl -sX POST $BASE/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@acme.example","password":"S3cr3t!Pw"}')
ACCESS=$(echo $PAIR | jq -r .access_token)
REFRESH=$(echo $PAIR | jq -r .refresh_token)

# 3. Refresh tokens
NEW_PAIR=$(curl -sX POST $BASE/auth/refresh \
  -H 'Content-Type: application/json' \
  -d "{\"refresh_token\":\"$REFRESH\"}")

# 4. Logout
curl -sX POST $BASE/auth/logout \
  -H "Authorization: Bearer $ACCESS" \
  -H 'Content-Type: application/json' \
  -d "{\"refresh_token\":\"$REFRESH\"}"
# → 204 No Content
```

## Integrating into another FastAPI module

```python
from src.auth.router import router as auth_router
from src.auth.dependencies import get_current_user, require_role
from src.core.database import get_db

app.include_router(auth_router)

# Protect an endpoint (any authenticated user)
@app.get("/my-resource")
async def my_resource(
    current_user = Depends(get_current_user),
    db = Depends(get_db),
):
    ...

# Require a specific role
@app.delete("/admin-only")
async def admin_only(
    current_user = Depends(require_role("admin", "super_admin")),
):
    ...
```