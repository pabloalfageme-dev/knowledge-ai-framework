# Tasks: Authentication & Multi-Tenancy Foundation

**Input**: Design documents from `specs/001-auth-multitenancy/`

**Prerequisites**: plan.md ✅ | spec.md ✅ | research.md ✅ | data-model.md ✅ | contracts/ ✅

**Tests**: Included — required by Constitution §VIII (≥80% unit coverage + integration tests against real PostgreSQL).

**Organization**: Tasks grouped by user story to enable independent implementation and testing.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no shared dependencies)
- **[Story]**: Maps to user story from spec.md (US1–US5)

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project initialization — establishes the directory layout, dependency manifest, and tooling before any code is written.

- [x] T001 Create project directory structure: `src/auth/`, `src/core/`, `tests/auth/unit/`, `tests/auth/integration/`, `alembic/versions/`, `cli/`, `docs/adr/`
- [x] T002 Create `pyproject.toml` with all dependencies: FastAPI, PyJWT>=2, passlib[bcrypt], SQLAlchemy>=2, asyncpg, alembic, pydantic-settings, typer, uvicorn; dev: pytest, pytest-asyncio, pytest-cov, httpx, ruff
- [x] T003 [P] Create `Dockerfile` using `python:3.12-slim` base; install deps from pyproject.toml; expose port 8000
- [x] T004 [P] Create `docker-compose.yml` with two services: `db` (postgres:15, named volume, health check) and `app` (depends on db, mounts src, passes DATABASE_URL)
- [x] T005 [P] Create `.env.example` with all required variables: `DATABASE_URL`, `JWT_SECRET`, `ACCESS_TOKEN_EXPIRE_SECONDS=900`, `REFRESH_TOKEN_EXPIRE_DAYS=7`, `LOCKOUT_ATTEMPT_THRESHOLD=5`, `LOCKOUT_DURATION_MINUTES=15`, `APP_ENV=development`
- [x] T006 [P] Configure `ruff` in `pyproject.toml` (lint + format, line-length=100, Python 3.11 target)

**Checkpoint**: Repo structure, manifest, and tooling ready — no code yet.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core infrastructure that MUST be complete before ANY user story can begin.

**⚠️ CRITICAL**: No user story work starts until this phase is complete.

- [x] T007 Create `src/core/config.py`: `pydantic-settings` `Settings` class reading `DATABASE_URL` and `APP_ENV` from environment
- [x] T008 Create `src/core/database.py`: async SQLAlchemy engine (`create_async_engine`), `AsyncSessionLocal` factory, `get_db` FastAPI dependency, and `set_rls_context(session, org_id)` helper that executes `SET LOCAL app.current_org_id = :org_id` — used by all org-scoped DB operations
- [x] T009 [P] Create `src/auth/config.py`: `AuthSettings` reading `JWT_SECRET`, `ACCESS_TOKEN_EXPIRE_SECONDS`, `REFRESH_TOKEN_EXPIRE_DAYS`, `LOCKOUT_ATTEMPT_THRESHOLD`, `LOCKOUT_DURATION_MINUTES` from environment
- [x] T010 Create `src/auth/models.py`: SQLAlchemy ORM models for all four entities — `Organization` (id, name, status, created_at), `User` (id, organization_id, email, credential_hash, credential_type, role, status, failed_login_count, locked_until, token_version, created_at), `AuditLogEntry` (id, occurred_at, user_id, organization_id, event_type, ip_address), `RefreshToken` (id, user_id, organization_id, family_id, token_hash, created_at, expires_at, used_at); relationships declared
- [x] T011 Create Alembic setup: `alembic.ini` (async driver URL) and `alembic/env.py` configured for async SQLAlchemy with `target_metadata` pointing to `src/auth/models.py`
- [x] T012 Create `alembic/versions/001_auth_foundation.py`: `CREATE TABLE` for all four entities with all columns, FKs, and indexes from data-model.md; `CREATE ROLE kn_app NOLOGIN` and `kn_admin` with `BYPASSRLS`; `GRANT` table privileges; `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` on `users`, `audit_log`, `refresh_tokens`; `CREATE POLICY` for each (using `current_setting('app.current_org_id')::uuid`); `organizations` table is NOT RLS-restricted (super-admin must read it freely)
- [x] T013 [P] Create `src/auth/security.py`: `create_access_token(user_id, org_id, role, token_version)` → HS256 JWT with `sub`, `jti`, `org`, `role`, `tv`, `iat`, `exp`; `decode_access_token(token)` → dict or raises; `hash_password(plain)` → bcrypt via passlib; `verify_password(plain, hashed)` → bool; `generate_api_key()` → returns (raw_uuid, sha256_hash) pair
- [x] T014 [P] Create `src/auth/schemas.py`: Pydantic models — `SetupRequest`, `SetupResponse`, `LoginRequest`, `TokenPair`, `RefreshRequest`, `LogoutRequest`, `CreateUserRequest`, `UpdateUserRequest`, `UserSummary`, `UserDetail`, `CreateServiceAccountRequest`, `ServiceAccountCreated`, `AuditEntry`, `AuditLogResponse`, `CreateOrganizationRequest`, `UpdateOrganizationRequest`, `OrganizationDetail`, `SystemHealth`, `ErrorResponse`
- [x] T015 Create `src/main.py`: `FastAPI` app with lifespan, include `auth_router` from `src/auth/router.py`, global exception handlers for `HTTPException` and unhandled errors (log with request_id + tenant_id context)
- [x] T016 Create `tests/auth/integration/conftest.py`: async pytest fixtures — `engine` (creates all tables against test PostgreSQL), `db_session` (transaction per test, rolled back after), `test_client` (httpx `AsyncClient` bound to the FastAPI app); reads `DATABASE_URL` from environment

**Checkpoint**: Database schema, ORM models, security primitives, and test fixtures all ready — user story implementation can now begin.

---

## Phase 3: User Story 2 — Initial Deployment Setup (Priority: P1)

**Goal**: On a blank database, bootstrap the first organization and admin user via CLI or HTTP; reject a second run.

**Independent Test**: Run `python cli/setup.py` on a blank DB → org + admin created, admin can log in. Run again → non-zero exit with "already initialized" message.

- [x] T017 [US2] Implement `create_first_org_and_admin(org_name, admin_email, admin_password)` in `src/auth/service.py`: assert zero organizations exist (raise `AlreadyInitializedError` otherwise), create `Organization` row, create `User` row (role=admin, credential_type=password, bcrypt hash of password), commit; return org_id and user_id
- [x] T018 [US2] Create `cli/setup.py`: Typer app with `setup` command accepting `--org-name`, `--admin-email`, `--admin-password`; calls `create_first_org_and_admin`; prints success table or error message; exits non-zero on `AlreadyInitializedError`
- [x] T019 [US2] Add `POST /setup` endpoint to `src/auth/router.py`: calls same `create_first_org_and_admin` service; returns `201 SetupResponse` or `409` if already initialized; no auth required
- [x] T020 [US2] Create `tests/auth/integration/test_setup.py`: scenario 1 — blank DB → setup succeeds, org and admin returned, admin can call `POST /auth/login`; scenario 2 — second setup call returns 409 with clear error message

**Checkpoint**: A deployable blank system can be bootstrapped. US1 login flow can now be developed and tested end-to-end.

---

## Phase 4: User Story 1 — End User Login (Priority: P1) 🎯 MVP

**Goal**: Authenticated users log in, receive access + refresh tokens, refresh silently, and log out. All events are audited.

**Independent Test**: `POST /auth/login` with valid credentials → tokens returned. Token grants access to a protected endpoint returning only the user's org data. Refresh rotates the token. Replay of old refresh token is rejected with 401. Logout returns 204.

- [x] T021 [US1] Implement `write_audit_entry(session, event_type, ip_address, user_id=None, org_id=None)` in `src/auth/service.py`: inserts `AuditLogEntry` row; wrapped in `try/except` so failure is non-blocking — logs error to application logger and returns without raising
- [x] T022 [US1] Implement `authenticate_user(session, email, password, ip_address)` in `src/auth/service.py`: query user by email; if not found return generic 401 (no enumeration); check `locked_until` → 401 if still locked; `verify_password(password, user.credential_hash)`; on failure: increment `failed_login_count`, set `locked_until` if threshold reached, write `LOGIN_FAILURE` audit entry, return 401; on success: reset `failed_login_count=0`, write `LOGIN_SUCCESS` audit entry, call `_issue_token_pair()`
- [x] T023 [US1] Implement `_issue_token_pair(session, user)` private helper in `src/auth/service.py`: generate `family_id = uuid4()`; generate raw refresh token UUID; insert `RefreshToken` row (token_hash = sha256, expires_at from config); call `create_access_token` from security.py; return `TokenPair`
- [x] T024 [US1] Implement `refresh_tokens(session, raw_refresh_token, ip_address)` in `src/auth/service.py`: hash the incoming token; query `RefreshToken` by token_hash; if not found → 401; if `used_at` is not None → theft detected: mark all rows with same `family_id` as `used_at=now()`, return 401; if expired → 401; mark current row `used_at=now()`; look up user + org (check both active + token_version match); call `_issue_token_pair()`; write `TOKEN_REFRESH` audit entry
- [x] T025 [US1] Implement `logout(session, current_user, raw_refresh_token, ip_address)` in `src/auth/service.py`: find `RefreshToken` by token_hash scoped to current_user.id; set `used_at=now()`; write `LOGOUT` audit entry
- [x] T026 [US1] Create `src/auth/dependencies.py`: `get_current_user(token: str = Depends(oauth2_scheme), db = Depends(get_db))` → decode JWT; single query `SELECT u.*, o.status as org_status FROM users u JOIN organizations o ON u.organization_id = o.id WHERE u.id = :uid`; assert `u.status == active`, `o.status == active`, `u.token_version == token.tv`; call `set_rls_context(db, u.organization_id)`; return `User`; `require_role(*roles)` → dependency factory that wraps `get_current_user` and asserts role membership
- [x] T027 [US1] Add auth endpoints to `src/auth/router.py`: `POST /auth/login` → `authenticate_user` → `TokenPair`; `POST /auth/refresh` → `refresh_tokens` → `TokenPair`; `POST /auth/logout` → `logout` → 204; `GET /health` → `{"status": "ok"}` (no auth)
- [x] T028 [US1] Create `tests/auth/unit/test_security.py`: test `create_access_token` / `decode_access_token` round-trip; test token_version mismatch raises; test expired token raises; test `hash_password` / `verify_password`; test `generate_api_key` returns distinct pair with correct hash
- [x] T029 [US1] Create `tests/auth/integration/test_login.py`: all 6 US1 acceptance scenarios — valid login returns tokens + audit entry; wrong password returns 401 + audit entry; deactivated user returns 401; valid token accesses protected endpoint returning only org data; refresh issues new pair and invalidates old; refresh replay triggers 401; logout returns 204

**Checkpoint**: Core auth MVP is complete. A user can log in, use the API, refresh silently, and log out. All events are audited. This is the deployable MVP.

---

## Phase 5: User Story 3 — Organization Admin Manages Users (Priority: P2)

**Goal**: Org admins create, deactivate, change roles, unlock, and list users within their own org — and can create service accounts with API keys.

**Independent Test**: Log in as org admin → create user → new user logs in → deactivate user → deactivated user's login returns 401 → list users returns only own-org members → cross-org user action returns 403/404.

- [x] T030 [US3] Implement user management service functions in `src/auth/service.py`: `list_users(session, org_id, status_filter)`, `create_user(session, org_id, email, password, role)`, `update_user(session, org_id, user_id, status=None, role=None)` — increment `token_version` when deactivating; `unlock_user(session, org_id, user_id)` — reset `failed_login_count=0` and `locked_until=None`; cross-org access raises 404 (not 403, to avoid org enumeration)
- [x] T031 [US3] Implement `create_service_account(session, org_id, email, role)` in `src/auth/service.py`: call `generate_api_key()` from security.py; create `User` row with `credential_type=api_key`, `credential_hash=key_hash`; return user + raw api_key (returned only once)
- [x] T032 [US3] Add user management endpoints to `src/auth/router.py`: `GET /users` (admin+), `POST /users` (admin+), `PATCH /users/{user_id}` (admin+), `POST /users/{user_id}/unlock` (admin+); all protected by `require_role("admin", "super_admin")`
- [x] T033 [US3] Add `POST /service-accounts` endpoint to `src/auth/router.py`: protected by `require_role("admin")`; calls `create_service_account`; returns `ServiceAccountCreated` (api_key shown once)
- [x] T034 [US3] Create `tests/auth/integration/test_user_mgmt.py`: all 5 US3 acceptance scenarios — create user who can log in; deactivate user who then cannot log in; cross-org action rejected; role change reflected in next token; create service account + service account logs in with API key

**Checkpoint**: Org admins can self-serve team management without operator intervention.

---

## Phase 6: User Story 4 — Organization Admin Views Audit Log (Priority: P2)

**Goal**: Org admins retrieve the audit log scoped exclusively to their organization, ordered by time descending.

**Independent Test**: With audit entries from two orgs, org admin A's query returns only org A entries. No org B events appear.

- [ ] T035 [US4] Implement `get_audit_log(session, org_id, event_type=None, user_id=None, from_dt=None, to_dt=None, limit=100, offset=0)` in `src/auth/service.py`: query `AuditLogEntry` filtered by `organization_id = org_id`; apply optional filters; order by `occurred_at DESC`; return items + total count
- [ ] T036 [US4] Add `GET /audit` endpoint to `src/auth/router.py`: protected by `require_role("admin", "super_admin")`; query params: `event_type`, `user_id`, `from`, `to`, `limit`, `offset`; returns `AuditLogResponse`
- [ ] T037 [US4] Create `tests/auth/integration/test_audit_log.py`: scenario 1 — org admin receives entries scoped to their org, ordered by occurred_at DESC; scenario 2 — entries from a second org never appear in the first org's response

**Checkpoint**: Compliance requirement satisfied — admins can audit auth events for their org.

---

## Phase 7: User Story 5 — Super-Admin Manages Organizations (Priority: P3)

**Goal**: Super-admins create new orgs, deactivate existing orgs (blocking all their users), and view aggregate health metrics.

**Independent Test**: Create org → new org accepts first admin user. Deactivate org → its users cannot log in. System health returns aggregate counts with no user-identifiable data. Super-admin cannot access org-specific user list.

- [ ] T038 [US5] Implement org management service functions in `src/auth/service.py`: `create_organization(session, name)` — unique-name check, insert `Organization`; `deactivate_organization(session, org_id)` — set `status=inactive`; `get_system_health(session)` — aggregate counts query (no user-identifiable fields): `organization_count`, `active_organization_count`, `active_user_count`
- [ ] T039 [US5] Add org management endpoints to `src/auth/router.py`: `POST /organizations` (super_admin only), `PATCH /organizations/{org_id}` (super_admin only), `GET /system/health` (super_admin only); all protected by `require_role("super_admin")`
- [ ] T040 [US5] Create `tests/auth/integration/test_org_mgmt.py`: all 4 US5 acceptance scenarios — create org + admin logs in; deactivate org → users blocked; system health returns aggregates with no PII; super-admin blocked from org-specific user list

**Checkpoint**: All 5 user stories are independently functional. Full auth stack is complete.

---

## Phase 8: Polish & Cross-Cutting Concerns

**Purpose**: Security hardening, observability, DoD completion, end-to-end validation.

- [ ] T041 Create `tests/auth/integration/test_multitenancy.py`: SC-004 suite — for every protected endpoint, assert that a valid token from Org A cannot access Org B data (must receive 403 or 404 100% of the time); include edge cases: org_id in path vs. org_id in token; deactivated org tokens rejected
- [ ] T042 [P] Create `tests/auth/unit/test_service.py`: unit tests for service layer business logic — lockout counter increments and resets correctly; `locked_until` is set/cleared; `token_version` increment; refresh token theft detection (family revocation); `write_audit_entry` failure does not propagate exception
- [ ] T043 [P] Create `tests/auth/unit/test_dependencies.py`: unit tests for `get_current_user` — expired token raises 401; `token_version` mismatch raises 401; inactive user raises 401; inactive org raises 401; `require_role` raises 403 for insufficient role
- [ ] T044 [P] Create `src/auth/README.md` per Constitution §VIII DoD: purpose, inputs/outputs, all environment variables with defaults, usage example (how to include `auth_router` in a new FastAPI app, how to use `get_current_user` dependency)
- [ ] T045 Run `quickstart.md` validation scenarios end-to-end against Docker Compose stack; fix any gaps between spec and implementation
- [ ] T046 Run `pytest --cov=src/auth --cov-report=term-missing`; achieve ≥80% line coverage (Constitution §VIII); add targeted unit tests for any uncovered branches

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — start immediately
- **Foundational (Phase 2)**: Requires Phase 1 — **BLOCKS all user stories**
- **US2 (Phase 3)**: Requires Phase 2 — no dependency on other user stories
- **US1 (Phase 4)**: Requires Phase 2 + Phase 3 (for E2E testing; unit tests can run sooner)
- **US3 (Phase 5)**: Requires Phase 4 (depends on `get_current_user` and `authenticate_user`)
- **US4 (Phase 6)**: Requires Phase 4 (audit entries are generated by login flow) — can run in parallel with Phase 5
- **US5 (Phase 7)**: Requires Phase 2 (org model), independent of US3/US4 for implementation — integration test requires Phase 4 for login
- **Polish (Phase 8)**: Requires all user story phases complete

### User Story Dependencies

```
Phase 1 (Setup)
    └── Phase 2 (Foundational)
            ├── Phase 3 (US2 Setup)
            │       └── Phase 4 (US1 Login) ← MVP
            │               ├── Phase 5 (US3 User Mgmt)
            │               ├── Phase 6 (US4 Audit Log)  ← parallel with US3
            │               └── Phase 7 (US5 Org Mgmt)   ← parallel with US3/US4
            └── Phase 7 (US5 Org Mgmt) ← org model ready after Phase 2
```

### Parallel Opportunities per Phase

**Phase 1**: T003, T004, T005, T006 all parallel after T001+T002.

**Phase 2**: T009, T013, T014 parallel after T007+T008+T010. T011 parallel with T013+T014. T016 parallel with T011.

**Phase 4 (US1)**:
```
T021 (audit helper)    ← run first (depended on by T022+T024+T025)
T022 (authenticate)    ← depends on T021, T023
T023 (_issue_pair)     ← parallel with T021
T024 (refresh)         ← depends on T023
T025 (logout)          ← depends on T023
T026 (dependencies)    ← parallel with T022-T025
T027 (router)          ← depends on T022-T026
T028 (unit tests)      ← parallel with T022-T025 (different files)
T029 (int tests)       ← after T027
```

**Phase 5 (US3)**: T030 and T031 parallel. T032 and T033 parallel after T030+T031. T034 after T032+T033.

**Phase 6 (US4)**: T035 → T036 → T037 (linear, small phase).

**Phase 8**: T042, T043, T044 all parallel after their respective story phases.

---

## Parallel Example: Phase 4 (US1)

```bash
# Run in parallel (different files, no shared state):
Task T021: "write_audit_entry helper in src/auth/service.py"
Task T023: "_issue_token_pair helper in src/auth/service.py"
Task T026: "get_current_user dependency in src/auth/dependencies.py"
Task T028: "unit tests in tests/auth/unit/test_security.py"

# Then run (depends on T021 + T023):
Task T022: "authenticate_user in src/auth/service.py"
Task T024: "refresh_tokens in src/auth/service.py"
Task T025: "logout in src/auth/service.py"

# Then run (depends on T022-T026):
Task T027: "auth endpoints in src/auth/router.py"

# Finally (depends on T027):
Task T029: "integration tests in tests/auth/integration/test_login.py"
```

---

## Implementation Strategy

### MVP First (US2 + US1)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational (CRITICAL — blocks everything)
3. Complete Phase 3: US2 (bootstrap)
4. Complete Phase 4: US1 (login flow)
5. **STOP AND VALIDATE**: Run `pytest tests/auth/` and quickstart Scenarios 1–2
6. This is a deployable, demoable auth system

### Incremental Delivery

| Phase | Adds | Demo-able After? |
|-------|------|-----------------|
| 1+2 | Project skeleton + DB schema | No |
| 3 (US2) | First org + admin bootstrapped | With CLI only |
| 4 (US1) | Login, refresh, logout, audit | ✅ MVP |
| 5 (US3) | User management, service accounts | ✅ Multi-user |
| 6 (US4) | Audit log query | ✅ Compliance |
| 7 (US5) | Org management by super-admin | ✅ Full system |
| 8 | Tests, docs, coverage | ✅ Ship-ready |

---

## Notes

- `[P]` = different files, no incomplete-task dependencies — safe to parallelise
- `[US*]` label maps each task to its user story for traceability and independent testing
- RLS policies live in `alembic/versions/001_auth_foundation.py` (T012) — must run before any service layer test
- `token_version` is incremented by `update_user(status=inactive)` (T030) — this invalidates all active tokens for the deactivated user
- Audit writes are non-blocking (T021) — test that a simulated write failure does NOT cause the login to fail (T042)
- Constitution §VIII DoD requires: ≥80% unit coverage (T046), integration test against real PostgreSQL (T029+), README.md (T044)
- Service account API key is returned **once** at creation time (T031/T033) — subsequent reads return the hash only