# Tasks: Authentication & Multi-Tenancy Foundation

**Input**: Design documents from `specs/001-auth-multitenancy/`

**Prerequisites**: plan.md ✅ | spec.md ✅ | research.md ✅ | data-model.md ✅ | contracts/auth.yaml ✅ | contracts/admin.yaml ✅

**Tests**: Required by Constitution §VIII — ≥80% unit coverage + integration tests against real PostgreSQL (no mocks).

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no blocking dependencies)
- **[Story]**: Maps to user story from spec.md (US1–US5)
- Exact file paths included in all task descriptions

## Path Conventions

Single project layout — all source under repository root:

- Source: `src/auth/`, `src/core/`
- Tests: `tests/auth/unit/`, `tests/auth/integration/`
- Migrations: `alembic/versions/`
- CLI: `cli/`

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project initialization — establishes the directory layout, dependency manifest, and tooling before any code is written.

- [x] T001 Create project directory structure: `src/auth/`, `src/core/`, `tests/auth/unit/`, `tests/auth/integration/`, `alembic/versions/`, `cli/`, `docs/adr/`
- [x] T002 Create `pyproject.toml` with all dependencies: FastAPI, PyJWT>=2, passlib[bcrypt], SQLAlchemy>=2, asyncpg, alembic, pydantic-settings, typer, uvicorn; dev: pytest, pytest-asyncio, pytest-cov, httpx, ruff
- [x] T003 [P] Create `Dockerfile` using `python:3.12-slim` base; install deps from pyproject.toml; expose port 8000
- [x] T004 [P] Create `docker-compose.yml` with two services: `db` (postgres:15, named volume, health check) and `app` (depends on db, mounts src, passes DATABASE_URL)
- [x] T005 [P] Create `.env.example` with all required variables: `DATABASE_URL`, `JWT_SECRET`, `ACCESS_TOKEN_EXPIRE_SECONDS=900`, `REFRESH_TOKEN_EXPIRE_DAYS=7`, `LOCKOUT_ATTEMPT_THRESHOLD=5`, `LOCKOUT_DURATION_MINUTES=15`, `REVOCATION_CACHE_TTL_SECONDS=30`, `APP_ENV=development`
- [x] T006 [P] Configure `ruff` in `pyproject.toml` (lint + format, line-length=100, Python 3.11 target)

**Checkpoint**: Repo structure, manifest, and tooling ready — no code yet.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core infrastructure that MUST be complete before ANY user story can begin.

**⚠️ CRITICAL**: No user story work starts until this phase is complete.

- [x] T007 Create `src/core/config.py`: `pydantic-settings` `Settings` class reading `DATABASE_URL` and `APP_ENV` from environment
- [x] T008 Create `src/core/database.py`: async SQLAlchemy engine (`create_async_engine`), `AsyncSessionLocal` factory, `get_db` FastAPI dependency, and `set_rls_context(session, org_id)` helper that executes `SET LOCAL app.current_org_id = :org_id`; kn_admin support implemented via `set_admin_context(session)` helper (Option B: `SET LOCAL ROLE kn_admin`) — T038–T040 US5 service methods must call it for all cross-org operations
- [x] T009 [P] Create `src/auth/config.py`: `AuthSettings` reading `JWT_SECRET`, `ACCESS_TOKEN_EXPIRE_SECONDS`, `REFRESH_TOKEN_EXPIRE_DAYS`, `LOCKOUT_ATTEMPT_THRESHOLD`, `LOCKOUT_DURATION_MINUTES`, `REVOCATION_CACHE_TTL_SECONDS` (default 30) from environment
- [x] T010 Create `src/auth/models.py`: SQLAlchemy ORM models for all five entities — `Organization` (id, name, status, created_at), `User` (id, organization_id, email, credential_hash, credential_type, role, status, failed_login_count, locked_until, token_version, created_at), `AuditLogEntry` (id, occurred_at, user_id, organization_id, event_type, ip_address), `RefreshToken` (id, user_id, organization_id, family_id, token_hash, created_at, expires_at, used_at), `RevokedToken` (id, jti, user_id, expires_at); all relationships declared; indexes match data-model.md
- [x] T011 Create Alembic setup: `alembic.ini` (async driver URL) and `alembic/env.py` configured for async SQLAlchemy with `target_metadata` pointing to `src/auth/models.py`
- [x] T012 Create `alembic/versions/001_auth_foundation.py`: `CREATE TABLE` for all five entities with all columns, FKs, and indexes from data-model.md; `CREATE ROLE kn_app NOLOGIN` and `kn_admin NOLOGIN BYPASSRLS`; `GRANT` table privileges; `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` on `users`, `audit_log`, `refresh_tokens`; `CREATE POLICY` for each using `current_setting('app.current_org_id', true)::uuid`; `organizations` table is NOT RLS-restricted; `downgrade()` drops all in reverse order; kn_admin wiring: `GRANT kn_admin TO kn_app` added (enables SET LOCAL ROLE escalation per T008 Option B)
- [x] T013 [P] Create `src/auth/security.py`: `create_access_token(user_id, org_id, role, token_version, settings)` → HS256 JWT with claims `{sub, jti, org, role, tv, iat, exp}`; `decode_access_token(token, settings)` → dict or raises 401; `hash_password(plain, settings)` → bcrypt via passlib; `verify_password(plain, hashed)` → bool; `generate_api_key()` → `(raw_uuid_str, sha256_hex_hash)` pair; `hash_api_key(key)` → SHA-256 hex digest
- [x] T014 [P] Create `src/auth/schemas.py`: Pydantic v2 models — `SetupRequest`, `SetupResponse`, `LoginRequest`, `TokenPair`, `RefreshRequest`, `LogoutRequest`, `CreateUserRequest`, `UpdateUserRequest`, `UserSummary`, `UserDetail`, `CreateServiceAccountRequest`, `ServiceAccountCreated`, `AuditEntry`, `AuditLogResponse`, `CreateOrganizationRequest`, `UpdateOrganizationRequest`, `OrganizationDetail`, `SystemHealth`, `ErrorResponse`
- [x] T015 Create `src/main.py`: `FastAPI` app with lifespan, include `auth_router` and `admin_router` from `src/auth/router.py`, global exception handlers for `HTTPException` and unhandled errors (log with request_id + tenant_id context)
- [x] T016 Create `tests/auth/integration/conftest.py`: async pytest fixtures — `engine` (creates all tables against test PostgreSQL, enables RLS), `db_session` (transaction per test, rolled back after), `async_client` (httpx `AsyncClient` bound to the FastAPI app); helper fixtures: `make_org`, `make_user`, `make_admin`, `make_super_admin`; reads `DATABASE_URL` from environment

**Checkpoint**: Database schema (5 tables), ORM models, security primitives, Pydantic schemas, and test fixtures all ready — user story implementation can now begin.

---

## Phase 3: User Story 2 — Initial Deployment Setup (Priority: P1)

**Goal**: On a blank database, bootstrap the first organization and admin user via CLI or HTTP; reject a second run.

**Independent Test**: Run `python cli/setup.py --org-name "Acme" --admin-email admin@acme.example --admin-password S3cr3t!` on blank DB → org + admin created, admin can log in immediately. Run again → non-zero exit with "already initialized" message.

- [x] T017 [US2] Implement `create_first_org_and_admin(org_name, admin_email, admin_password, db, settings)` in `src/auth/service.py`: within single atomic transaction assert zero organizations exist (raise `AlreadyInitializedError` otherwise); create `Organization` row; create `User` row (role=admin, credential_type=password, bcrypt hash of password, status=active); commit; return `SetupResponse`; DB unique constraint on `organizations.name` handles concurrent race → maps to `AlreadyInitializedError` via `IntegrityError`
- [x] T018 [US2] Create `cli/setup.py`: Typer app with `setup` command accepting `--org-name`, `--admin-email`, `--admin-password` (prompted if omitted); calls `create_first_org_and_admin` via `asyncio.run`; prints success or error message; exits non-zero on `AlreadyInitializedError`
- [x] T019 [US2] Add `POST /setup` endpoint to `src/auth/router.py`: calls same `create_first_org_and_admin` service; returns `201 SetupResponse` on success; maps `AlreadyInitializedError` to `409 ErrorResponse(detail="System already initialized")`; no authentication required
- [x] T020 [US2] Create `tests/auth/integration/test_setup.py`: scenario 1 — blank DB → `POST /setup` returns 201, org and admin IDs returned, admin immediately logs in via `POST /auth/login`; scenario 2 — second `POST /setup` returns 409 with "already initialized" detail

**Checkpoint**: A deployable blank system can be bootstrapped. US1 login flow can now be developed and tested end-to-end.

---

## Phase 4: User Story 1 — End User Login (Priority: P1) 🎯 MVP

**Goal**: Authenticated users log in, receive access + rotating refresh tokens, refresh silently, and log out. Lockout after configured consecutive failures. Every event is audited.

**Independent Test**: `POST /auth/login` with valid credentials → `TokenPair` returned. Token grants access to protected endpoint returning only the user's org data. Refresh rotates both tokens (old refresh rejected). 5 consecutive wrong passwords lock the account. `POST /auth/logout` → 204.

- [x] T021 [US1] Implement `write_audit_entry(session, event_type, ip_address, user_id=None, org_id=None)` in `src/auth/service.py`: inserts `AuditLogEntry` row; wrapped in `try/except` — failure is non-blocking (log error to app logger, return without raising)
- [x] T022 [US1] Implement `authenticate_user(session, email, password, ip_address, settings)` in `src/auth/service.py`: query user by email; if not found → write non-blocking LOGIN_FAILURE audit, raise uniform 401 (no enumeration); check `locked_until` — if still locked → write LOGIN_FAILURE audit, raise 401; `verify_password(password, user.credential_hash)` (or SHA-256 path for api_key credential_type); on failure: increment `failed_login_count`; if count >= `LOCKOUT_ATTEMPT_THRESHOLD` set `locked_until = now() + LOCKOUT_DURATION_MINUTES`, write non-blocking ACCOUNT_LOCKED audit entry; write LOGIN_FAILURE audit entry; raise 401; on success: reset `failed_login_count=0`, clear `locked_until`, write non-blocking LOGIN_SUCCESS audit entry; assert `user.status == 'active'` and `user.organization.status == 'active'`; return User
- [x] T023 [US1] Implement `_issue_token_pair(session, user, settings, family_id=None)` private helper in `src/auth/service.py`: generate `family_id = family_id or uuid4()`; generate raw refresh UUID; insert `RefreshToken(id=refresh_uuid, family_id=family_id, token_hash=sha256_hash, expires_at=now()+REFRESH_TOKEN_EXPIRE_DAYS)`; call `create_access_token` from security.py; return `TokenPair`
- [x] T024 [US1] Implement `refresh_tokens(session, raw_refresh_token, ip_address, settings)` in `src/auth/service.py`: hash incoming UUID via `hash_api_key`; query `RefreshToken` by `token_hash`; if not found → 401; if `used_at IS NOT NULL` → theft detected: `UPDATE RefreshToken SET used_at=now() WHERE family_id=row.family_id AND used_at IS NULL`; commit; return 401; if `expires_at < now()` → 401; set `row.used_at = now()`; look up user + org (check both active + `token_version` matches JWT claim); call `_issue_token_pair(session, user, settings, family_id=row.family_id)`; write non-blocking TOKEN_REFRESH audit entry; return new `TokenPair`
- [x] T025 [US1] Implement `logout(session, current_user, raw_refresh_token, access_jti, access_exp, ip_address)` in `src/auth/service.py`: find `RefreshToken` by token_hash scoped to `current_user.id`; set `used_at=now()`; insert `RevokedToken(jti=access_jti, user_id=current_user.id, expires_at=access_exp)`; write non-blocking LOGOUT audit entry; commit
- [x] T026 [US1] Create `src/auth/dependencies.py`: `get_current_user(token=Depends(oauth2_scheme), db=Depends(get_db)) -> CurrentUser`: decode JWT via `decode_access_token`; check in-process TTL cache keyed by JTI (TTL = `REVOCATION_CACHE_TTL_SECONDS`, default 30 s); on cache miss: query `SELECT u.*, o.status as org_status FROM users u JOIN organizations o ON u.organization_id = o.id WHERE u.id = :uid`; assert `u.status == 'active'`, `o.status == 'active'`, `u.token_version == token.tv`; check `revoked_tokens WHERE jti = token.jti` (logout detection); cache positive result; call `set_rls_context(db, u.organization_id)`; return `CurrentUser` dataclass; `require_role(*roles)` → dependency factory wrapping `get_current_user`, raises 403 if `current_user.role not in roles`
- [x] T027 [US1] Add auth endpoints to `src/auth/router.py`: `POST /auth/login` → `authenticate_user` then `_issue_token_pair` → `TokenPair` (all failure paths return uniform `ErrorResponse` 401 — no enumeration per FR-016); `POST /auth/refresh` → `refresh_tokens` → `TokenPair` or 401; `POST /auth/logout` → `Depends(get_current_user)`, call `logout`, return 204; `GET /health` → `{"status": "ok", "version": "1.0.0"}` (no auth required)
- [x] T028 [US1] Create `tests/auth/unit/test_security.py`: test `create_access_token` / `decode_access_token` round-trip with correct claims; expired token raises 401; tampered signature raises 401; `token_version` embedded correctly in `tv` claim; `hash_password` / `verify_password` round-trip; `generate_api_key` returns (raw, hash) pair where hash matches `hash_api_key(raw)`
- [x] T029 [US1] Create `tests/auth/integration/test_login.py`: all 6 US1 acceptance scenarios — valid login returns `TokenPair` + LOGIN_SUCCESS audit entry; wrong password returns 401 + LOGIN_FAILURE audit entry; deactivated user login returns 401; valid token on `GET /users` returns only own-org data; `POST /auth/refresh` returns new `TokenPair` with different token values; old refresh token replay returns 401 (family revoked); logout returns 204; 5 consecutive wrong passwords trigger ACCOUNT_LOCKED audit entry, 6th attempt with correct password still returns 401

**Checkpoint**: Core auth MVP complete — login, refresh rotation, theft detection, lockout, logout, and audit all verified. Deployable MVP.

---

## Phase 5: User Story 3 — Organization Admin Manages Users (Priority: P2)

**Goal**: Org admins create, deactivate, change roles, unlock, and list users within their own org — and can create service accounts with API keys. Cross-org operations return 404.

**Independent Test**: Admin creates user → new user logs in. Admin deactivates user → login denied (immediate — new login reads live DB). Admin attempts action on other-org user → 404. Admin creates service account → API key authenticates successfully.

- [x] T030 [US3] Implement user management service functions in `src/auth/service.py`: `list_users(session, org_id, status_filter)` → SELECT within org (RLS also enforces scope); `create_user(session, org_id, email, password, role, settings)` → INSERT with bcrypt-hashed password; `update_user(session, org_id, user_id, status, role)` → SELECT with org scope (raise 404 if not found), PATCH status/role; if role changed increment `token_version` to invalidate existing tokens; if deactivated also increment `token_version`; `unlock_user(session, org_id, user_id)` → reset `failed_login_count=0`, `locked_until=None`; cross-org access raises 404 (not 403 — prevents org enumeration)
- [x] T031 [US3] Implement `create_service_account(session, org_id, email, role, settings)` in `src/auth/service.py`: call `generate_api_key()` from security.py; create `User` row with `credential_type='api_key'`, `credential_hash=key_hash` (SHA-256 hash — verified at login with `hash_api_key` comparison, not bcrypt); return `(user, raw_api_key)`; raw key returned once only — not stored
- [x] T032 [US3] Add user management endpoints to `src/auth/router.py`: `GET /users` (require_role admin+), `POST /users` (require_role admin+), `PATCH /users/{user_id}` (require_role admin+), `POST /users/{user_id}/unlock` (require_role admin+); all use `set_rls_context` from TenantContext; map duplicate email `IntegrityError` to 409
- [x] T033 [US3] Add `POST /service-accounts` endpoint to `src/auth/router.py`: `require_role("admin")`; calls `create_service_account`; returns 201 `ServiceAccountCreated` with plain `api_key` in response body (shown once only — not retrievable again)
- [x] T034 [US3] Create `tests/auth/integration/test_user_mgmt.py`: all 5 US3 acceptance scenarios — create user who can log in immediately; deactivate user who then cannot log in (401 — new login reads live DB state per SC-007); cross-org PATCH returns 404; role change reflected in next issued token (`token_version` incremented); create service account, returned `api_key` authenticates via `POST /auth/login`; duplicate email returns 409

**Checkpoint**: Org admins can self-serve team management without operator intervention.

---

## Phase 6: User Story 4 — Organization Admin Views Audit Log (Priority: P2)

**Goal**: Org admins retrieve the audit log scoped exclusively to their organization, with filtering and pagination, ordered by `occurred_at DESC`.

**Independent Test**: With audit entries from two orgs in the DB, org admin A's `GET /audit` returns only org A entries (count verified). Filter by `event_type=LOGIN_FAILURE` returns only failures. Results ordered `occurred_at DESC`.

- [ ] T035 [US4] Implement `get_audit_log(session, org_id, event_type, user_id, from_dt, to_dt, limit, offset)` in `src/auth/service.py`: query `AuditLogEntry WHERE organization_id = org_id` (RLS also enforces scope via `set_rls_context`); apply optional filters: `event_type` (enum: LOGIN_SUCCESS, LOGIN_FAILURE, LOGOUT, TOKEN_REFRESH, ACCOUNT_LOCKED), `user_id`, `occurred_at >= from_dt`, `occurred_at <= to_dt`; `ORDER BY occurred_at DESC`; `LIMIT limit OFFSET offset` (limit max 500); separate count query for total; return `AuditLogResponse(items=[AuditEntry(...)], total=total_count)`
- [ ] T036 [US4] Add `GET /audit` endpoint to `src/auth/router.py`: `require_role("admin", "super_admin")`; query params: `event_type: str | None`, `user_id: UUID | None`, `from_: datetime | None = Query(None, alias="from")`, `to: datetime | None`, `limit: int = Query(100, le=500)`, `offset: int = 0`; call `get_audit_log(session, current_user.org_id, ...)`; return `AuditLogResponse`
- [ ] T037 [P] [US4] Create `tests/auth/integration/test_audit_log.py`: setup — create Org A and Org B, generate events for each (login, failed login, logout); scenario 1 — Org A admin `GET /audit` returns only Org A entries, Org B entries absent (count matches exactly); scenario 2 — `?event_type=LOGIN_FAILURE` returns only LOGIN_FAILURE entries for Org A; scenario 3 — `?from=<ts>&to=<ts>` date range filter restricts results correctly; scenario 4 — results are `occurred_at DESC` ordered; scenario 5 — pagination (`?limit=1&offset=0` vs `?limit=1&offset=1`) returns different entries; scenario 6 — `total` field reflects unfiltered org entry count

**Checkpoint**: Compliance requirement satisfied — admins can audit auth events for their org with no cross-tenant leakage.

---

## Phase 7: User Story 5 — Super-Admin Manages Organizations (Priority: P3)

**Goal**: Super-admins create new orgs, deactivate existing orgs (all org users denied on next login attempt), and view aggregate health metrics with no user-identifiable data.

**Independent Test**: Super-admin creates org (201), creates user in that org. Super-admin deactivates org → user login returns 401 immediately (new login reads live DB). `GET /system/health` returns counts with no names or emails. Super-admin `GET /users` returns 403.

- [ ] T038 [US5] Implement `create_organization`, `deactivate_organization`, `get_system_health` in `src/auth/service.py` — `create_organization(session, name)`: INSERT `Organization(name=name, status='active')`; raise 409 on `IntegrityError` (duplicate name); commit; return `Organization`; uses `kn_admin` DB role for cross-org write (bypass RLS); `deactivate_organization(session, org_id)`: UPDATE `organizations SET status='inactive' WHERE id=org_id`; raise 404 if not found; commit; return updated `Organization`; uses `kn_admin` role; `get_system_health(session)`: `SELECT COUNT(*) AS org_count, COUNT(*) FILTER (WHERE status='active') AS active_org_count FROM organizations`; `SELECT COUNT(*) FROM users WHERE status='active'` as `active_user_count`; return `SystemHealth` with no org names, emails, or individual user data; uses `kn_admin` role
- [ ] T039 [US5] Add org management endpoints to `src/auth/router.py`: all `require_role("super_admin")`; `POST /organizations` → `create_organization`, return 201 `OrganizationDetail`; map duplicate name to 409; `PATCH /organizations/{org_id}` → `deactivate_organization`, return 200 `OrganizationDetail` or 404; `GET /system/health` → `get_system_health`, return `SystemHealth`
- [ ] T040 [P] [US5] Create `tests/auth/integration/test_org_mgmt.py`: scenario 1 — super-admin `POST /organizations` returns 201 `OrganizationDetail` with `status='active'`; scenario 2 — user created in new org can log in; scenario 3 — super-admin `PATCH /organizations/{id}` `status=inactive` returns 200; user in deactivated org `POST /auth/login` returns 401 immediately (login bypasses revocation cache, reads live DB per SC-007); scenario 4 — `GET /system/health` returns `{organization_count, active_organization_count, active_user_count}` with no names or emails; scenario 5 — super-admin `GET /users` returns 403; scenario 6 — org admin `POST /organizations` returns 403; scenario 7 — duplicate org name returns 409

**Checkpoint**: All 5 user stories independently functional. Full auth stack complete.

---

## Phase 8: Polish & Cross-Cutting Concerns

**Purpose**: Security hardening, observability, Constitution §VIII DoD completion, end-to-end validation.

- [ ] T041 Create `tests/auth/integration/test_multitenancy.py` — SC-004 cross-tenant suite: create Org A and Org B, each with admin and regular user; using Org A admin token assert: `GET /users` returns only Org A users (Org B users absent); `PATCH /users/{org_b_user_id}` returns 404; `POST /users` with Org A token creates user in Org A only; `GET /audit` returns only Org A entries; `GET /users/{org_b_user_id}/unlock` returns 404; verify all protected endpoints return 403 or 404 for cross-tenant access 100% of the time; also verify: deactivated org token rejected within one REVOCATION_CACHE_TTL window
- [ ] T042 [P] Create `tests/auth/unit/test_service.py` — unit tests for service business logic with DB `AsyncSession` mocked at boundary: `authenticate_user` increments `failed_login_count` on wrong password; 5th failure sets `locked_until` and writes ACCOUNT_LOCKED audit entry alongside LOGIN_FAILURE; correct password while `locked_until > now()` returns 401; `refresh_tokens` with `used_at IS NOT NULL` revokes entire family (verify UPDATE covers all family members with same `family_id`); `logout` inserts JTI into `revoked_tokens`; `write_audit_entry` failure (mock INSERT raising exception) does NOT propagate — primary auth operation still completes; `update_user` with `role` change increments `token_version`
- [ ] T043 [P] Create `tests/auth/unit/test_dependencies.py` — unit tests for `get_current_user` with session mocked: valid JWT + active user + matching `token_version` → returns `CurrentUser`; expired JWT → raises 401; `token_version` mismatch → raises 401; `user.status='inactive'` → raises 401; `org.status='inactive'` → raises 401; JTI present in `revoked_tokens` → raises 401; second call within TTL with same JTI → DB not queried again (verify mock call count = 1); `require_role("admin")` with `super_admin` user → raises 403
- [ ] T044 [P] Create `src/auth/README.md` per Constitution §VIII DoD: module purpose; inputs (HTTP requests, JWT tokens) and outputs (DB records, token pairs); env vars reference table (all vars with types, defaults, and description); Docker usage example; `curl` quickstart for setup → login → refresh → logout flow; how to include `auth_router` and `get_current_user` dependency in another FastAPI module
- [ ] T045 Run `quickstart.md` end-to-end validation: `docker compose up -d db && alembic upgrade head && uvicorn src.main:app --reload`; execute Scenarios 1–6 from `quickstart.md/`; verify each `curl` command returns the documented expected output; record any discrepancies as follow-up bugs
- [ ] T046 Run `pytest --cov=src/auth --cov-report=term-missing`; fix coverage gaps until ≥80% line coverage is achieved for all modules in `src/auth/` (Constitution §VIII); add targeted unit tests for uncovered branches (typical gaps: error paths in service layer, edge cases in refresh rotation, RLS context setting)

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — start immediately
- **Foundational (Phase 2)**: Requires Phase 1 — **BLOCKS all user stories**
- **US2 (Phase 3)**: Requires Phase 2 — no dependency on other user stories
- **US1 (Phase 4)**: Requires Phase 2; US2 used in integration tests but service is independent
- **US3 (Phase 5)**: Requires Phase 4 (uses `get_current_user` dependency and login flow in integration tests)
- **US4 (Phase 6)**: Requires Phase 4 (audit entries are generated by login/logout flow); can run in parallel with Phase 5
- **US5 (Phase 7)**: Requires Phase 2 (org model); integration tests require Phase 4 for login; implementation is independent
- **Polish (Phase 8)**: Requires all user story phases complete

### User Story Dependencies

```
Phase 1 (Setup)
    └── Phase 2 (Foundational)
            ├── Phase 3 (US2 — Setup)
            │       └── Phase 4 (US1 — Login) ← MVP
            │               ├── Phase 5 (US3 — User Mgmt)
            │               ├── Phase 6 (US4 — Audit Log)   ← parallel with US3
            │               └── Phase 7 (US5 — Org Mgmt)    ← parallel with US3/US4
            └── Phase 7 (US5 — Org Mgmt)  ← implementation independent after Phase 2
```

### Within Each User Story

- Unit tests [P] can be written in parallel with implementation (different files)
- Service methods are sequential within `service.py` if one calls another
- Router endpoints depend on all service methods for that story
- Integration tests run after the router is implemented

### Parallel Opportunities per Phase

**Phase 1**: T003, T004, T005, T006 all parallel after T001+T002.

**Phase 2**: T009, T013, T014 parallel after T007+T008+T010. T011 parallel with T013+T014. T016 parallel with T011.

**Phase 6 (US4)**: T037 [P] can be written while T035+T036 are being implemented (different files).

**Phase 7 (US5)**: T040 [P] can be written while T038+T039 are being implemented.

**Phase 8**: T042, T043, T044 all parallel — different files, no shared dependencies.

---

## Parallel Example: Phase 4 (US1)

```bash
# Run in parallel (different files, no shared state):
Task T021: write_audit_entry helper in src/auth/service.py
Task T028: unit tests in tests/auth/unit/test_security.py

# Then run (depends on T021):
Task T022: authenticate_user in src/auth/service.py
Task T023: _issue_token_pair helper in src/auth/service.py

# Then run (depends on T022 + T023):
Task T024: refresh_tokens in src/auth/service.py
Task T025: logout in src/auth/service.py
Task T026: get_current_user dependency in src/auth/dependencies.py  ← parallel with T024/T025

# Then run (depends on T022-T026):
Task T027: auth endpoints in src/auth/router.py

# Finally (depends on T027):
Task T029: integration tests in tests/auth/integration/test_login.py
```

---

## Implementation Strategy

### MVP First (US2 + US1)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational (**CRITICAL** — blocks everything)
3. Complete Phase 3: US2 (bootstrap)
4. Complete Phase 4: US1 (login flow)
5. **STOP AND VALIDATE**: Run `pytest tests/auth/` and quickstart.md Scenarios 1–2
6. This is a deployable, demoable auth system

### Incremental Delivery

| Phase | Adds | Demo-able After? |
|-------|------|-----------------|
| 1+2 | Project skeleton + DB schema (5 tables, RLS) | No |
| 3 (US2) | First org + admin bootstrapped via CLI | With CLI only |
| 4 (US1) | Login, refresh, logout, lockout, audit | ✅ MVP |
| 5 (US3) | User management, service accounts | ✅ Multi-user |
| 6 (US4) | Audit log query with filters | ✅ Compliance |
| 7 (US5) | Org management by super-admin | ✅ Full system |
| 8 | Cross-tenant tests, unit tests, docs, coverage | ✅ Ship-ready |

---

## Notes

- `[P]` = different files, no incomplete-task dependencies — safe to parallelise
- `[US*]` label maps each task to its user story for traceability and independent testing
- Constitution §VIII DoD: ≥80% unit coverage (T046), integration tests against real PostgreSQL (T029+), README.md (T044)
- Audit writes are non-blocking (T021) — primary auth operation completes even if audit `INSERT` fails; verified in T042
- `token_version` incremented on deactivation and role change (T030) — invalidates all existing tokens for that user without a JTI blocklist
- RLS requires `SET LOCAL app.current_org_id = :org_id` at each transaction start via `set_rls_context` — missing this causes empty result sets, not errors
- `super_admin` operations use `kn_admin` DB role (`BYPASSRLS`) for cross-org writes (T038); `kn_app` role used for all tenant-scoped operations
- New login attempts always read live DB state (bypass revocation cache) — deactivated users are rejected immediately (SC-007a); already-issued tokens are rejected within one `REVOCATION_CACHE_TTL_SECONDS` window (SC-007b)
- Service account API key hashed with SHA-256 for storage in `credential_hash`; verified at login by comparing `hash_api_key(submitted_password)` to stored hash (see T031)
- Email is unique system-wide across all organizations (not per-org) — single UNIQUE INDEX on `users.email`
