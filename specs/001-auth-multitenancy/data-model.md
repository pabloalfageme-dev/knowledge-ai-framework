# Data Model: Authentication & Multi-Tenancy Foundation

**Feature**: `001-auth-multitenancy` | **Date**: 2026-07-04

## Entity Overview

```
Organization ──< User ──< AuditLogEntry
                  │
                  ├──< RefreshToken
                  └──< RevokedToken (access token JTIs)
```

---

## Organizations

Top-level tenant boundary. Every piece of data in the system is scoped to an organization.

| Column | Type | Constraints | Notes |
|--------|------|-------------|-------|
| `id` | UUID | PK, default gen_random_uuid() | |
| `name` | VARCHAR(255) | NOT NULL, UNIQUE | System-wide uniqueness |
| `status` | VARCHAR(10) | NOT NULL, default 'active' | Values: `active`, `inactive` |
| `created_at` | TIMESTAMPTZ | NOT NULL, default now() | UTC |

**Indexes**: `organizations(name)` unique, `organizations(status)` for health queries.

**State transitions**:
- `active` → `inactive`: super-admin deactivation (FR-011); all users denied auth immediately
- `inactive` → `active`: not in v1 scope (reactivation is a future operator task)

---

## Users

Represents both human users (email + password) and service accounts (email + API key).
Belongs to exactly one organization. `super_admin` users have `organization_id = NULL`.

| Column | Type | Constraints | Notes |
|--------|------|-------------|-------|
| `id` | UUID | PK, default gen_random_uuid() | |
| `organization_id` | UUID | FK → organizations(id), nullable | NULL only for super_admin |
| `email` | VARCHAR(255) | NOT NULL, UNIQUE | Login identifier |
| `credential_hash` | VARCHAR(255) | NOT NULL | bcrypt hash (password or API key) |
| `credential_type` | VARCHAR(10) | NOT NULL, default 'password' | Values: `password`, `api_key` |
| `role` | VARCHAR(15) | NOT NULL | Values: `super_admin`, `admin`, `user` |
| `status` | VARCHAR(10) | NOT NULL, default 'active' | Values: `active`, `inactive` |
| `failed_login_count` | INTEGER | NOT NULL, default 0 | Reset to 0 on successful login |
| `locked_until` | TIMESTAMPTZ | nullable | NULL = not locked; set on lockout trigger |
| `token_version` | INTEGER | NOT NULL, default 1 | Increment to invalidate all user tokens instantly |
| `created_at` | TIMESTAMPTZ | NOT NULL, default now() | UTC |

**Indexes**: `users(email)` unique; `users(organization_id)` for org-scoped queries;
`users(organization_id, status)` for active-user lookups.

**Constraints**:
- `role = 'super_admin'` → `organization_id IS NULL`
- `role IN ('admin', 'user')` → `organization_id IS NOT NULL`
- Email must be unique across all organizations (login identifier is global)

**State transitions**:
- `active` → `inactive`: org admin deactivation (FR-007); immediate auth denial
- `inactive` → `active`: org admin reactivation (future; not in v1 user stories but field exists)
- `locked_until` set: after `LOCKOUT_ATTEMPT_THRESHOLD` consecutive failures (FR-016)
- `locked_until` cleared: auto (threshold passed) or manual unlock by org admin (FR-016)
- `failed_login_count` reset: on any successful login

---

## AuditLogEntry

Append-only record of every authentication event. Never updated or deleted after insertion.

| Column | Type | Constraints | Notes |
|--------|------|-------------|-------|
| `id` | UUID | PK, default gen_random_uuid() | |
| `occurred_at` | TIMESTAMPTZ | NOT NULL, default now() | UTC; not modifiable |
| `user_id` | UUID | FK → users(id), nullable | NULL for unknown-email failures |
| `organization_id` | UUID | FK → organizations(id), nullable | NULL for unknown-email failures |
| `event_type` | VARCHAR(20) | NOT NULL | See event types below |
| `ip_address` | VARCHAR(45) | NOT NULL | IPv4 or IPv6 |

**Event types**: `LOGIN_SUCCESS`, `LOGIN_FAILURE`, `LOGOUT`, `TOKEN_REFRESH`,
`ACCOUNT_LOCKED`

**Indexes**: `audit_log(organization_id, occurred_at DESC)` for org admin log queries (FR-009);
`audit_log(user_id, occurred_at DESC)` for per-user history.

**Write behaviour**: If an audit write fails, the primary auth operation still completes and
the failure is logged to the application error log (non-blocking per spec Assumptions).

---

## RefreshTokens

Tracks issued refresh tokens with rotation support and theft detection via family groups.

| Column | Type | Constraints | Notes |
|--------|------|-------------|-------|
| `id` | UUID | PK, default gen_random_uuid() | Also the raw token value returned to client |
| `user_id` | UUID | FK → users(id) NOT NULL | |
| `organization_id` | UUID | FK → organizations(id), nullable | Mirrors user's org; NULL for super_admin |
| `family_id` | UUID | NOT NULL | Groups all rotations from the same login event |
| `token_hash` | VARCHAR(255) | NOT NULL | SHA-256 hash of the raw token UUID |
| `created_at` | TIMESTAMPTZ | NOT NULL, default now() | UTC |
| `expires_at` | TIMESTAMPTZ | NOT NULL | Configurable TTL from created_at |
| `used_at` | TIMESTAMPTZ | nullable | NULL = active; non-NULL = rotated (invalidated) |

**Indexes**: `refresh_tokens(token_hash)` for lookup on use; `refresh_tokens(family_id)` for
family revocation; `refresh_tokens(user_id, expires_at)` for cleanup.

**Rotation protocol**:
1. Client presents raw token UUID → server hashes it → looks up by `token_hash`
2. If found AND `used_at IS NULL` AND `expires_at > now()` → valid
3. Mark current row `used_at = now()`; insert new row in same `family_id`; return new token
4. If found AND `used_at IS NOT NULL` → **theft detected**: set `used_at = now()` on ALL rows
   in the same `family_id` (entire family revoked); return 401

**Cleanup**: Background task (or pruning query on each refresh) removes rows where
`expires_at < now()`.

---

---

## Token Payload (JWT Claims)

Access tokens are HS256-signed JWTs. Standard claims:

| Claim | Type | Value |
|-------|------|-------|
| `sub` | string | User UUID |
| `jti` | string | Unique token UUID |
| `org` | string | Organization UUID (null for super_admin) |
| `role` | string | `super_admin` \| `admin` \| `user` |
| `tv` | int | Token version — must match `users.token_version`; mismatch = reject |
| `iat` | int | Issued-at (Unix timestamp) |
| `exp` | int | Expiry (Unix timestamp, default +15 min) |

---

## Tenant Isolation Pattern

Isolation is enforced at the **database layer** via PostgreSQL Row-Level Security (RLS),
aligning with Constitution principle VI.

**RLS setup**:
- All tenant-scoped tables (`users`, `audit_log`, `refresh_tokens`) have RLS enabled and a
  policy: `USING (organization_id = current_setting('app.current_org_id')::uuid)`
- The application connects as a non-superuser role (`kn_app`) that cannot bypass RLS
- At the start of every DB transaction, the service layer executes:
  `SET LOCAL app.current_org_id = :org_id`
- Super-admin operations that intentionally span organizations use a separate DB role
  (`kn_admin`) with `BYPASSRLS` privilege, invoked only for explicitly cross-org endpoints

**Per-request authentication check**:
The `get_current_user` FastAPI dependency performs one DB query after JWT signature
verification, joining `users` + `organizations` to assert:
1. `users.status = 'active'`
2. `users.token_version = token.tv` (mismatch means the user's tokens were revoked)
3. `organizations.status = 'active'`

If any condition fails, the request is rejected with 401. This single query covers all
immediate deactivation and revocation scenarios with no extra table needed.