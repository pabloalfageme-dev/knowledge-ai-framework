# Research: Authentication & Multi-Tenancy Foundation

**Feature**: `001-auth-multitenancy` | **Date**: 2026-07-04

All unknowns from the Technical Context are resolved below. No NEEDS CLARIFICATION items remain.

---

## Decision 1: Multi-Tenancy Enforcement — RLS vs Application-Level Filtering

**Decision**: PostgreSQL Row-Level Security (RLS)

**Rationale**: Constitution principle VI states data isolation "MUST be enforced at the
database layer." RLS is the database layer — it filters queries automatically at the engine
level even if application code contains a bug. Application-level filtering (`WHERE
organization_id = :org_id`) is application-layer enforcement; a single missing predicate in
any query silently exposes all tenants. For a shared-tenant framework where a breach
simultaneously affects all clients, the defense-in-depth guarantee of RLS outweighs the
added setup complexity.

**Implementation**:
- All tenant-scoped tables have RLS enabled with policy:
  `USING (organization_id = current_setting('app.current_org_id')::uuid)`
- Application role `kn_app` cannot bypass RLS
- Service layer sets `SET LOCAL app.current_org_id = :org_id` at transaction start
- Super-admin cross-org operations use role `kn_admin` with `BYPASSRLS`
- Alembic migrations include `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` and
  `CREATE POLICY` statements alongside `CREATE TABLE`

**Alternatives considered**:
- *Application-level filtering*: simpler Alembic migrations, easier to debug; rejected
  because a single missed predicate silently leaks cross-tenant data — unacceptable for
  a shared multi-client framework. May be introduced as a secondary safety layer in the
  service base class (defence-in-depth), but RLS is the primary enforcement mechanism.

---

## Decision 2: JWT Access Token Revocation Strategy

**Decision**: `token_version` counter on the `users` table; no JTI blocklist table required

**Rationale**: Every authenticated request already loads the user + org from the DB to check
active status. Adding a single `token_version` integer to the users table costs nothing extra
in that query. The JWT carries a `tv` claim; if `token.tv != users.token_version`, the token
is rejected immediately. To deactivate a user and invalidate all their tokens instantly,
increment `token_version` and set `status = inactive`. For logout, only the refresh token
needs to be invalidated; the access token expires naturally within the configured TTL
(default 15 min), which is an accepted trade-off for stateless JWT.

**Per-request auth check (single DB query)**:
```sql
SELECT u.id, u.status, u.token_version, u.role, u.organization_id,
       o.status AS org_status
FROM users u
JOIN organizations o ON u.organization_id = o.id
WHERE u.id = :user_id
```
Reject if: `u.status != 'active'` OR `token.tv != u.token_version` OR
`o.status != 'active'`.

**Alternatives considered**:
- *Per-JTI blocklist table*: provides true instant revocation for logout but requires an
  extra table, a PK lookup on every request, and a pruning job. The access-token TTL of
  15 min makes the marginal security benefit small; rejected in favour of simplicity.
- *Redis blacklist*: common pattern but adds operational overhead (Redis deployment,
  cache TTL synchronisation); rejected per Constitution principle V (Simplicity First /
  YAGNI — no Redis in the current stack).

---

## Decision 3: Refresh Token Rotation + Theft Detection

**Decision**: `refresh_tokens` table with `family_id` + `used_at` (rotate-on-use,
family revocation on replay detection)

**Rationale**: OAuth 2.0 Security Best Current Practice (RFC 9700) recommends refresh
token rotation. Token family tracking provides theft detection: if a rotated-out token
is replayed, the entire family is revoked, forcing the legitimate user to re-authenticate.
The schema is minimal — five columns plus indexes — and imposes no additional latency
beyond the existing DB query for access token validation.

**Rotation protocol**:
1. Client presents raw token UUID → server SHA-256 hashes it → looks up `token_hash`
2. Found + `used_at IS NULL` + `expires_at > now()` → valid; proceed
3. Mark current row `used_at = now()`; insert new row with same `family_id`; return new token
4. Found + `used_at IS NOT NULL` → **theft signal**; set `used_at = now()` on all rows
   sharing this `family_id`; return 401

**Schema** (see data-model.md for full definition):
- `id` (UUID PK — also the raw token value given to the client)
- `user_id`, `organization_id`, `family_id`
- `token_hash` (SHA-256 of `id`; looked up on use)
- `created_at`, `expires_at`, `used_at` (nullable)

**Alternatives considered**:
- *Non-rotating refresh tokens*: simpler but a stolen token grants indefinite access until
  manual revocation; rejected per Constitution principle VI.
- *`replaced_by` FK pointer*: adds an additional column for chain traversal; useful for
  audit/debug but not required for theft detection; deferred (YAGNI).

---

## Decision 4: Python Libraries

**Decision**: PyJWT 2.x, passlib[bcrypt], SQLAlchemy 2.x (async), asyncpg, Alembic,
pydantic-settings

**Rationale**:
- **PyJWT 2.x**: actively maintained, minimal API, native Python. `python-jose` is less
  actively maintained and has had CVEs; avoided.
- **passlib[bcrypt]**: industry standard for password hashing in Python; bcrypt's work
  factor is configurable and time-resistant by design.
- **SQLAlchemy 2.x async + asyncpg**: async-native ORM pairs naturally with FastAPI's async
  request handling; asyncpg is the most performant pure-Python PostgreSQL async driver.
- **Alembic**: pairs with SQLAlchemy; migrations are Python files that can include
  arbitrary SQL for RLS policy setup alongside schema changes.
- **pydantic-settings**: reads env vars with type validation; standard FastAPI pattern.

**Alternatives considered**:
- *Tortoise ORM / databases*: less mature async ORM ecosystem; SQLAlchemy 2.x async is
  production-proven.
- *psycopg3*: viable; asyncpg is marginally faster for high-throughput scenarios and has
  wider community adoption.

---

## Decision 5: Initial Setup Mechanism

**Decision**: Typer-based CLI command (`cli/setup.py`) that calls the same service layer
as the API

**Rationale**: The spec states setup "is triggered via a dedicated CLI command or a protected
bootstrap endpoint." A CLI command is simpler, has no network surface to secure, and is
idiomatic for Docker/ECS deployments (run as a one-off task). Typer integrates cleanly with
FastAPI projects and produces auto-generated `--help` output.

**Alternatives considered**:
- *Bootstrap HTTP endpoint* (`POST /setup`): included in contracts for completeness and
  for local dev convenience, but the CLI is the primary delivery mechanism. The HTTP
  endpoint is protected by checking for zero existing organizations.

---

## All NEEDS CLARIFICATION Items: Resolved

| Item | Resolution |
|------|-----------|
| Multi-tenancy enforcement mechanism | PostgreSQL RLS (see Decision 1) |
| Token revocation approach | `token_version` counter + status checks (see Decision 2) |
| Refresh token rotation schema | Family-based `refresh_tokens` table (see Decision 3) |
| Python JWT library | PyJWT 2.x (see Decision 4) |
| Initial setup delivery | Typer CLI + optional HTTP bootstrap endpoint (see Decision 5) |