# Implementation Plan: Authentication & Multi-Tenancy Foundation

**Branch**: `001-auth-multitenancy` | **Date**: 2026-07-04 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/001-auth-multitenancy/spec.md`

## Summary

Build the authentication and multi-tenancy foundation for KnowledgeAI: a FastAPI service with
JWT-based auth (HS256, access + rotating refresh tokens), three roles (super_admin / admin /
user), strict organization-level data isolation enforced at the application layer, account
lockout after configurable failed attempts, a revocation store for immediate deactivation
effect, service account / API key support, and a full authentication audit log. This module is
the prerequisite gate every other framework module depends on.

## Technical Context

**Language/Version**: Python 3.11+

**Primary Dependencies**: FastAPI, PyJWT 2.x, passlib[bcrypt], SQLAlchemy 2.x (async),
Alembic, asyncpg (PostgreSQL async driver), pydantic-settings

**Storage**: PostgreSQL 15+ — five tables: `organizations`, `users`, `audit_log`,
`refresh_tokens`, `revoked_tokens`

**Testing**: pytest + pytest-asyncio; httpx (async test client); real PostgreSQL instance for
integration tests (no mocks per constitution §VIII)

**Target Platform**: Linux server, Docker container, AWS EC2 / ECS

**Project Type**: web-service (FastAPI REST API, backend-only)

**Performance Goals**: login endpoint p95 < 200ms; deactivation effective on next request
(no restart); audit log entry visible within 1 s of event (SC-003)

**Constraints**: every env-var driven; no hardcoded secrets or config values; organization
isolation enforced at the database layer via PostgreSQL RLS (`SET LOCAL app.current_org_id`
per transaction); application role `kn_app` cannot bypass RLS

**Scale/Scope**: SME pilot — 3 client organizations, ~10–50 users each; single-process
deployment initially; modular so other framework modules can import the auth dependency without
pulling in unrelated code

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Reusability First | ✅ PASS | Auth module has no client-specific logic; all behaviour driven by config; reusable across all 3 pilot clients |
| II. Modularity & Separation of Concerns | ✅ PASS | `src/auth/` is independently importable; exposes a FastAPI router and a `get_current_user` dependency; zero hard imports of other framework modules |
| III. Configuration Over Code | ✅ PASS | JWT secret, token TTLs, lockout thresholds, password rules all via env vars; no forking needed per client |
| IV. Provider Abstraction | ✅ N/A | No LLM or vector-store calls in this module |
| V. Simplicity First | ✅ PASS | Plain Python + FastAPI + SQLAlchemy; no orchestration framework; no premature abstractions |
| VI. Security by Default | ✅ PASS | Multi-tenant isolation day-1; revocation store; account lockout; HS256 JWTs; bcrypt hashing; no public endpoints exposing org data |
| VII. Observability & Cost Transparency | ✅ PASS | Audit log covers all auth events; `/health` endpoint included; app errors logged with request_id + tenant_id context |
| VIII. Test-Driven Quality | ✅ PASS | Unit tests (≥80% coverage) + integration tests against live PostgreSQL required by DoD |

**Post-Phase-1 Re-check** (after design artifacts generated):

| Principle | Status | Post-design notes |
|-----------|--------|------------------|
| I. Reusability First | ✅ PASS | RLS + token_version are framework-level constructs; no client-specific logic in any artifact |
| II. Modularity | ✅ PASS | `src/auth/` self-contained; exposes router + `get_current_user` dependency; zero cross-module imports |
| III. Configuration Over Code | ✅ PASS | DB role names, JWT_SECRET, TTLs, lockout thresholds all env-var driven |
| IV. Provider Abstraction | ✅ N/A | No LLM/vector-store calls |
| V. Simplicity First | ✅ PASS | PyJWT + passlib + SQLAlchemy + Alembic; Typer CLI; RLS migration complexity is justified by Security by Default |
| VI. Security by Default | ✅ PASS | RLS at DB layer; token_version; bcrypt; HS256; account lockout; no public data endpoints |
| VII. Observability | ✅ PASS | Full audit log; `/health` endpoint; errors logged with request_id + tenant_id |
| VIII. Test-Driven Quality | ✅ PASS | Unit (≥80%) + integration tests against real PostgreSQL; type hints mandatory |

**Complexity Tracking**: No violations — table omitted.

## Project Structure

### Documentation (this feature)

```text
specs/001-auth-multitenancy/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/           # Phase 1 output
│   ├── auth.yaml        # OpenAPI paths for auth endpoints
│   └── admin.yaml       # OpenAPI paths for user/org management
└── tasks.md             # Phase 2 output (/speckit-tasks — not created here)
```

### Source Code (repository root)

```text
src/
├── auth/
│   ├── __init__.py
│   ├── config.py          # Auth settings (JWT secret, TTLs, lockout thresholds)
│   ├── models.py          # SQLAlchemy ORM models (Organization, User, AuditLogEntry,
│   │                      #   RefreshToken, RevokedToken)
│   ├── schemas.py         # Pydantic request/response schemas
│   ├── security.py        # JWT encode/decode, password hashing, API key generation
│   ├── service.py         # Business logic (login, refresh, logout, user CRUD, org CRUD)
│   ├── dependencies.py    # FastAPI dependencies (get_current_user, require_role,
│   │                      #   TenantContext)
│   └── router.py          # FastAPI APIRouter (all /auth, /users, /organizations,
│                          #   /audit, /health endpoints)
├── core/
│   ├── __init__.py
│   ├── database.py        # Async SQLAlchemy engine + session factory
│   └── config.py          # Base app settings (DATABASE_URL, environment)
└── main.py                # FastAPI app instantiation, router registration

tests/
├── auth/
│   ├── unit/
│   │   ├── test_security.py       # JWT encode/decode, hashing, API key generation
│   │   ├── test_service.py        # Business logic with DB session mocked at boundary
│   │   └── test_dependencies.py   # Dependency injection behaviour
│   └── integration/
│       ├── conftest.py            # DB setup/teardown, test client fixtures
│       ├── test_login.py          # US1 scenarios
│       ├── test_setup.py          # US2 scenarios
│       ├── test_user_mgmt.py      # US3 scenarios
│       ├── test_audit_log.py      # US4 scenarios
│       ├── test_org_mgmt.py       # US5 scenarios
│       └── test_multitenancy.py   # SC-004 cross-tenant rejection suite

alembic/
├── env.py
├── script.py.mako
└── versions/
    └── 001_auth_foundation.py     # Initial schema migration

cli/
└── setup.py                       # One-time deployment bootstrap CLI (US2)

Dockerfile
docker-compose.yml                 # App + PostgreSQL for local development
alembic.ini
pyproject.toml
.env.example
```

**Structure Decision**: Single-project layout. All auth code lives under `src/auth/`;
`src/core/` holds the database session factory shared by future modules. The `cli/` directory
holds the one-time setup command (US2). No frontend — this feature is backend-only.