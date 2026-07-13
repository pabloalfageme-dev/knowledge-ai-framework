# Auth Module

Multi-tenant authentication and authorization for KnowledgeAI.

## Overview

**Inputs**: HTTP requests with JWT Bearer tokens or plain credentials  
**Outputs**: JWT `TokenPair` (access + refresh), PostgreSQL audit rows, user records

## Architecture

```
src/auth/
  config.py        # AuthSettings via pydantic-settings
  models.py        # SQLAlchemy ORM: Organization, User, AuditLogEntry, RefreshToken, RevokedToken
  schemas.py       # Pydantic I/O schemas
  security.py      # JWT encode/decode, bcrypt, SHA-256 helpers
  service.py       # Business logic (no HTTP concern)
  dependencies.py  # FastAPI dependencies: get_current_user, require_role
  router.py        # HTTP endpoints mounted at /
```

## Environment Variables

| Variable | Type | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | str | — | asyncpg DSN e.g. `postgresql+asyncpg://user:pass@host/db` |
| `JWT_SECRET` | str | — | HS256 signing key (≥32 bytes recommended) |
| `ACCESS_TOKEN_EXPIRE_SECONDS` | int | 900 | Access token lifetime (15 min) |
| `REFRESH_TOKEN_EXPIRE_DAYS` | int | 7 | Refresh token lifetime |
| `LOCKOUT_ATTEMPT_THRESHOLD` | int | 5 | Failed logins before account lockout |
| `LOCKOUT_DURATION_MINUTES` | int | 15 | Lockout duration |
| `REVOCATION_CACHE_TTL_SECONDS` | int | 30 | JTI in-process cache TTL |

## Docker

```bash
docker compose up -d db
docker compose run --rm app alembic upgrade head
docker compose up app
```

## Quick start (curl)

```bash
# 1. Bootstrap first org + admin
curl -sX POST http://localhost:8000/setup \
  -H 'Content-Type: application/json' \
  -d '{"organization_name":"Acme","admin_email":"admin@acme.example","admin_password":"S3cr3t!Pw"}'

# 2. Login
TOKEN=$(curl -sX POST http://localhost:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@acme.example","password":"S3cr3t!Pw"}' | jq -r .access_token)

# 3. Refresh tokens
curl -sX POST http://localhost:8000/auth/refresh \
  -H 'Content-Type: application/json' \
  -d '{"refresh_token":"<refresh_token_uuid>"}'

# 4. Logout
curl -sX POST http://localhost:8000/auth/logout \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"refresh_token":"<refresh_token_uuid>"}'
```

## Integrating into another FastAPI module

```python
from src.auth.router import router as auth_router
from src.auth.dependencies import get_current_user, require_role
from src.core.database import get_db

app.include_router(auth_router)

# Protect an endpoint
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

## Database roles

| Role | BYPASSRLS | Purpose |
|---|---|---|
| `kn_app` | No | Tenant-scoped operations (RLS enforced) |
| `kn_admin` | Yes | Cross-org lookups: login, refresh, super-admin endpoints |

`get_current_user` starts as `kn_admin` to resolve any user (including `super_admin` with `organization_id=NULL`), then reverts to `kn_app` for regular-tenant users after setting `app.current_org_id`.
