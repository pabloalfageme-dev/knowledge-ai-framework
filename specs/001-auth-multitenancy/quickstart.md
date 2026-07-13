# Quickstart Validation Guide: Authentication & Multi-Tenancy Foundation

**Feature**: `001-auth-multitenancy` | **Date**: 2026-07-04

This guide describes how to stand up the auth module locally and validate each user story
end-to-end. It assumes Docker Compose is available and the repository has been cloned.

References: [data-model.md](data-model.md) | [contracts/auth.yaml](contracts/auth.yaml) |
[contracts/admin.yaml](contracts/admin.yaml)

---

## Prerequisites

```bash
# 1. Copy environment template
cp .env.example .env
# Minimum required values in .env:
#   DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/knowledgeai
#   JWT_SECRET=<any-random-256-bit-string>
#   ACCESS_TOKEN_EXPIRE_SECONDS=900
#   REFRESH_TOKEN_EXPIRE_DAYS=7
#   LOCKOUT_ATTEMPT_THRESHOLD=5
#   LOCKOUT_DURATION_MINUTES=15

# 2. Start PostgreSQL
docker compose up -d db

# 3. Run migrations
alembic upgrade head

# 4. Start the API
uvicorn src.main:app --reload
```

The API is now available at `http://localhost:8000`. Interactive docs at
`http://localhost:8000/docs`.

---

## Scenario 1 — Initial Setup (US2)

```bash
# Bootstrap first organization and admin user
python cli/setup.py \
  --org-name "Acme Bikes" \
  --admin-email admin@acme.example \
  --admin-password S3cr3tPassword!

# Expected: organization + admin user created; exit 0

# Running setup a second time must fail
python cli/setup.py \
  --org-name "Another Org" \
  --admin-email other@example.com \
  --admin-password password123

# Expected: non-zero exit with message "System already initialized"
```

---

## Scenario 2 — End User Login Flow (US1)

```bash
BASE=http://localhost:8000

# 2a. Successful login
curl -s -X POST $BASE/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@acme.example","password":"S3cr3tPassword!"}' | jq .

# Expected: { "access_token": "...", "refresh_token": "...", "token_type": "bearer", "expires_in": 900 }

ACCESS=$(curl -s -X POST $BASE/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@acme.example","password":"S3cr3tPassword!"}' | jq -r .access_token)

REFRESH=$(curl -s -X POST $BASE/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@acme.example","password":"S3cr3tPassword!"}' | jq -r .refresh_token)

# 2b. Access a protected endpoint
curl -s $BASE/users -H "Authorization: Bearer $ACCESS" | jq .
# Expected: array containing the admin user (scoped to Acme Bikes only)

# 2c. Wrong password
curl -s -X POST $BASE/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@acme.example","password":"wrong"}' | jq .
# Expected: 401 — same error shape as unknown email (no enumeration)

# 2d. Token refresh (rotation)
NEW_PAIR=$(curl -s -X POST $BASE/auth/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"$REFRESH\"}")
echo $NEW_PAIR | jq .
# Expected: new access_token + new refresh_token (different values)

NEW_REFRESH=$(echo $NEW_PAIR | jq -r .refresh_token)

# 2e. Replay old refresh token (theft detection)
curl -s -X POST $BASE/auth/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"$REFRESH\"}" | jq .
# Expected: 401 — old token is already rotated; entire family revoked

# 2f. Logout
curl -s -X POST $BASE/auth/logout \
  -H "Authorization: Bearer $ACCESS" \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"$NEW_REFRESH\"}"
# Expected: 204 No Content
```

---

## Scenario 3 — User Management (US3)

```bash
# Log in as admin
ACCESS=$(curl -s -X POST $BASE/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@acme.example","password":"S3cr3tPassword!"}' | jq -r .access_token)

# 3a. Create a regular user
NEW_USER=$(curl -s -X POST $BASE/users \
  -H "Authorization: Bearer $ACCESS" \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@acme.example","password":"Alice1234!","role":"user"}')
echo $NEW_USER | jq .
USER_ID=$(echo $NEW_USER | jq -r .id)
# Expected: user created with role=user, status=active

# 3b. New user can log in
curl -s -X POST $BASE/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@acme.example","password":"Alice1234!"}' | jq .
# Expected: 200 with tokens

# 3c. Deactivate user
curl -s -X PATCH $BASE/users/$USER_ID \
  -H "Authorization: Bearer $ACCESS" \
  -H "Content-Type: application/json" \
  -d '{"status":"inactive"}' | jq .
# Expected: 200, status=inactive

# 3d. Deactivated user cannot log in (new login reads live DB — immediate)
curl -s -X POST $BASE/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@acme.example","password":"Alice1234!"}' | jq .
# Expected: 401 immediately (same shape as wrong password)
# Note: requests using an already-issued token are rejected within one revocation
#       cache window (default 30 s) — see REVOCATION_CACHE_TTL_SECONDS in .env

# 3e. Cross-organization rejection (create a second org to test)
# First, log in as super_admin (created via DB or CLI directly)
# Then create a second org, get a user from it, and verify the first admin
# cannot see or modify that user — 404 or 403 expected
```

---

## Scenario 4 — Audit Log (US4)

```bash
# 4a. Generate some events (login, failed login, logout)
# ... (use scenarios 2a-2f above)

# 4b. Query audit log as admin
curl -s "$BASE/audit" \
  -H "Authorization: Bearer $ACCESS" | jq '.items | length'
# Expected: count > 0

# 4c. Verify only own-org entries
curl -s "$BASE/audit" \
  -H "Authorization: Bearer $ACCESS" | jq '[.items[].event_type] | unique'
# Expected: only LOGIN_SUCCESS, LOGIN_FAILURE, LOGOUT, TOKEN_REFRESH, ACCOUNT_LOCKED
#           for Acme Bikes users — no entries from other organizations
```

---

## Scenario 5 — Super-Admin Creates Organization (US5)

```bash
# Log in as super_admin (set up via CLI or DB seed)
SA_ACCESS=$(curl -s -X POST $BASE/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"superadmin@knowledgeai.internal","password":"..."}' | jq -r .access_token)

# 5a. Create a new organization
NEW_ORG=$(curl -s -X POST $BASE/organizations \
  -H "Authorization: Bearer $SA_ACCESS" \
  -H "Content-Type: application/json" \
  -d '{"name":"Tourist Shop Palma"}')
echo $NEW_ORG | jq .
ORG_ID=$(echo $NEW_ORG | jq -r .id)
# Expected: 201, status=active

# 5b. Deactivate organization
curl -s -X PATCH $BASE/organizations/$ORG_ID \
  -H "Authorization: Bearer $SA_ACCESS" \
  -H "Content-Type: application/json" \
  -d '{"status":"inactive"}' | jq .
# Expected: 200, status=inactive

# 5c. Users in deactivated org cannot log in (requires a user in Tourist Shop first)

# 5d. System health (aggregate only, no user data)
curl -s $BASE/system/health \
  -H "Authorization: Bearer $SA_ACCESS" | jq .
# Expected: { "organization_count": N, "active_organization_count": M, "active_user_count": K }
```

---

## Scenario 6 — Service Account / API Key (FR-017)

```bash
# Log in as admin
ACCESS=$(curl -s -X POST $BASE/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@acme.example","password":"S3cr3tPassword!"}' | jq -r .access_token)

# 6a. Create service account
SA=$(curl -s -X POST $BASE/service-accounts \
  -H "Authorization: Bearer $ACCESS" \
  -H "Content-Type: application/json" \
  -d '{"email":"svc-ingest@acme.example","role":"user"}')
echo $SA | jq .
API_KEY=$(echo $SA | jq -r .api_key)
# Expected: api_key field present (shown only once)

# 6b. Service account authenticates with API key
curl -s -X POST $BASE/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"svc-ingest@acme.example\",\"password\":\"$API_KEY\"}" | jq .
# Expected: 200 with tokens scoped to Acme Bikes
```

---

## Running the Automated Test Suite

```bash
# Unit tests only (no DB required)
pytest tests/auth/unit/ -v

# Integration tests (requires live PostgreSQL)
docker compose up -d db
pytest tests/auth/integration/ -v

# Full suite with coverage
pytest --cov=src/auth --cov-report=term-missing
# Expected: ≥ 80% line coverage (Constitution §VIII)
```

---

## Cross-Tenant Isolation Smoke Test

```bash
# SC-004: using a valid token from Org A to access Org B data must be rejected 100%
# Automated in tests/auth/integration/test_multitenancy.py
pytest tests/auth/integration/test_multitenancy.py -v
# Expected: all cross-tenant access attempts return 403 or 404
```