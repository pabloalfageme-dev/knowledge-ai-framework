# Feature Specification: Authentication & Multi-Tenancy Foundation

**Feature Branch**: `001-auth-multitenancy`

**Created**: 2026-07-04

**Status**: Draft

**Input**: User description: "Build an authentication and multi-tenancy foundation for KnowledgeAI."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - End User Login (Priority: P1)

A user submits their credentials to the API and receives an access token and a refresh token.
They use the access token on all subsequent requests. The system enforces their organization
and role on every request automatically. When the access token expires they use the refresh
token to obtain a new one without re-entering credentials. An audit entry is recorded for
every event: login, logout, and refresh.

**Why this priority**: Authentication is the foundational gate everything else depends on.
No other user story can be built or tested without a working login flow.

**Independent Test**: Send a login request and verify: (1) valid token returned, (2) token
grants access to a protected endpoint and the response contains only the user's organization
data, (3) an audit entry is recorded with correct fields, (4) wrong password returns an error
with its own audit entry.

**Acceptance Scenarios**:

1. **Given** an active user with valid credentials, **When** they submit email and password,
   **Then** they receive an access token and refresh token, and a `LOGIN_SUCCESS` audit entry
   is recorded with timestamp, user id, organization id, and IP address.

2. **Given** a user with an incorrect password, **When** they submit credentials, **Then**
   authentication is rejected and a `LOGIN_FAILURE` audit entry is recorded.

3. **Given** a deactivated user account, **When** the user attempts to log in, **Then**
   access is denied and a `LOGIN_FAILURE` audit entry is recorded.

4. **Given** a valid access token, **When** it is used on a protected endpoint, **Then** the
   response contains only data belonging to the token-holder's organization.

5. **Given** a valid refresh token, **When** the user requests a new access token, **Then** a
   new access token and a new refresh token are issued, the old refresh token is invalidated,
   and a `TOKEN_REFRESH` audit entry is recorded.

6. **Given** an authenticated user, **When** they log out, **Then** a `LOGOUT` audit entry is
   recorded.

---

### User Story 2 - Initial Deployment Setup (Priority: P1)

On a fresh deployment with no organizations or users, an operator runs a one-time setup
process. They provide the first organization's name and the credentials for its first admin
user. The setup succeeds and the admin can immediately log in. Running the setup a second
time on a deployment that already has an organization is rejected.

**Why this priority**: Without the initial setup no accounts exist. It is a prerequisite for
every other user story and every client onboarding.

**Independent Test**: On a blank database, run the setup with valid inputs and verify: (1)
an organization is created, (2) the admin user can log in, (3) running setup again is rejected
with a clear error.

**Acceptance Scenarios**:

1. **Given** a fresh deployment with no organizations, **When** setup runs with a valid
   organization name and admin credentials, **Then** the organization and admin user are
   created and the admin can log in immediately.

2. **Given** a deployment where setup has already run, **When** setup is invoked again,
   **Then** it is rejected with a clear error message indicating the system is already
   initialized.

---

### User Story 3 - Organization Admin Manages Users (Priority: P2)

An organization admin creates new user accounts, deactivates existing ones, and changes
roles for users within their organization. They have no visibility into — and no effect
on — users in any other organization.

**Why this priority**: Every client deployment needs an admin who can onboard their team
without the framework operator intervening. Without this, every user addition requires
direct database access.

**Independent Test**: Log in as an org admin and verify: (1) a new user can be created and
can log in, (2) a deactivated user cannot log in, (3) listing users returns only the admin's
organization members, (4) attempting to act on a user from another organization is rejected.

**Acceptance Scenarios**:

1. **Given** an authenticated org admin, **When** they create a new user with email and role,
   **Then** the account is created within the admin's organization and the new user can log in.

2. **Given** an authenticated org admin, **When** they deactivate a user in their organization,
   **Then** that user can no longer authenticate.

3. **Given** an authenticated org admin, **When** they attempt to view or modify a user from
   a different organization, **Then** the request is rejected.

4. **Given** an authenticated org admin, **When** they change a user's role, **Then** the new
   role is reflected in that user's next issued access token.

5. **Given** an authenticated org admin, **When** they create a service account, **Then** an API
   key is generated and returned once; the service account can immediately authenticate using
   that key and receives a token scoped to the admin's organization.

---

### User Story 4 - Organization Admin Views Audit Log (Priority: P2)

An organization admin views the authentication audit log for their organization. They see
all auth events for their users — login attempts, logouts, token refreshes — and nothing
from any other organization.

**Why this priority**: Compliance and accountability are requirements for every client
deployment. Admins need visibility into who accessed the system and when.

**Independent Test**: With audit entries from multiple organizations in the system, an org
admin queries the log and verifies that only entries belonging to their organization appear.

**Acceptance Scenarios**:

1. **Given** an authenticated org admin, **When** they request the audit log, **Then** they
   receive entries scoped to their organization only, ordered by timestamp descending.

2. **Given** audit entries from multiple organizations exist, **When** an org admin queries
   the log, **Then** no entries from other organizations appear in the response.

---

### User Story 5 - Super-Admin Manages Organizations (Priority: P3)

A super-admin creates new client organizations and deactivates existing ones. They can view
aggregate system health (counts, statuses) across all organizations but cannot access any
organization's users, documents, or data.

**Why this priority**: New client onboarding requires creating an organization. This is an
infrequent operator task and not on the critical path for any client's daily operation.

**Independent Test**: Verify: (1) a new organization can be created and accepts a first user,
(2) deactivating an organization prevents its users from logging in, (3) the health view
returns aggregate counts with no user-identifiable data.

**Acceptance Scenarios**:

1. **Given** an authenticated super-admin, **When** they create a new organization with a name,
   **Then** the organization is active and an admin user can immediately be created within it.

2. **Given** an authenticated super-admin, **When** they deactivate an organization, **Then**
   all users in that organization are prevented from authenticating.

3. **Given** an authenticated super-admin, **When** they request system health, **Then** they
   receive aggregate metrics (organization count, active user count) with no user-identifiable
   or organization-specific data.

4. **Given** an authenticated super-admin, **When** they attempt to access the users or data of
   a specific organization, **Then** the request is rejected.

---

### Edge Cases

- **Resolved**: When a token is used after the issuing user is deactivated (or after their
  organization is deactivated), the revocation check rejects the request immediately with a 401;
  deactivation writes to the revocation store and takes effect on the very next request.
- What happens if the initial setup endpoint is called concurrently by two processes on a fresh deployment?
- **Resolved**: Login failure responses for a wrong password, locked account, or non-existent email are indistinguishable to the caller (FR-016). Failed attempts increment a counter; lockout triggers after the configured threshold.
- What happens when an audit log write fails — does it block the primary authentication response?

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST enforce organization-level data isolation at the database layer;
  no query executed within one organization's context MAY return data belonging to another.
- **FR-002**: All protected endpoints MUST reject unauthenticated requests; no endpoint that
  accesses or returns organization data MAY be publicly accessible.
- **FR-003**: Every access token MUST carry the user's organization identifier, role, and a
  unique token identifier (JTI). Token claims MUST be verifiable cryptographically; in addition,
  every authenticated request MUST check the token's JTI (or the user/organization active status)
  against a revocation store to enforce immediate effect of user and organization deactivation —
  deactivated users and organizations MUST be rejected without waiting for token expiry.
- **FR-004**: The system MUST support exactly three roles: `super_admin` (framework-level,
  not scoped to any organization), `admin` (organization-level), and `user` (organization-level).
- **FR-005**: The system MUST record an audit entry for every authentication event: successful
  login, failed login, logout, and token refresh. Each entry MUST include: UTC timestamp,
  user identifier (nullable for unknown-user failures), organization identifier (nullable for
  unknown-user failures), event type, and IP address.
- **FR-006**: An org admin MUST be able to create user accounts scoped to their own organization.
- **FR-007**: An org admin MUST be able to deactivate user accounts within their organization;
  deactivated users MUST be denied authentication immediately.
- **FR-008**: An org admin MUST be able to assign and change roles (`admin` / `user`) for
  members of their organization only.
- **FR-009**: An org admin MUST be able to retrieve the audit log filtered to their organization.
- **FR-010**: A super-admin MUST be able to create new organizations.
- **FR-011**: A super-admin MUST be able to deactivate organizations; all users in a deactivated
  organization MUST be denied authentication.
- **FR-012**: A super-admin MUST be able to view aggregate system health metrics without access
  to organization-specific data or individual user identities.
- **FR-013**: The system MUST provide a one-time initial setup mechanism that creates the first
  organization and its first admin user; it MUST be permanently disabled once any organization exists.
- **FR-014**: Human users MUST authenticate via email and password; service accounts MUST
  authenticate via API keys; both produce the same token type consumed by the API.
- **FR-015**: Access tokens MUST have a configurable expiry. A refresh token mechanism MUST
  allow obtaining a new access token without re-entering credentials, subject to the refresh
  token's own configurable expiry. Refresh tokens MUST rotate on every use: the presented
  refresh token is invalidated and a new refresh token is issued alongside the new access token.
  A used (rotated-out) refresh token presented again MUST be rejected and SHOULD trigger
  revocation of the entire token family to detect theft.
- **FR-016**: After a configurable number of consecutive failed login attempts (default: 5),
  the account MUST be locked for a configurable duration (default: 15 minutes). Lockout MUST
  be recorded as an audit entry. A locked account MUST clear automatically after the configured
  window; an org admin MAY also manually unlock accounts within their organization. Error
  responses for a locked account, a wrong password, or an unknown email MUST be
  indistinguishable to the caller (prevents user enumeration).
- **FR-017**: An org admin MUST be able to create service accounts and generate API keys scoped
  to their own organization. Service accounts MUST be subject to the same activation, deactivation,
  and role-assignment rules as human user accounts. API key values MUST be returned to the admin
  only at creation time and MUST NOT be retrievable thereafter (stored as a hash).

### Key Entities

- **Organization**: identifier, name, status (active/inactive), created_at — the top-level
  tenant boundary; all data is scoped to an organization.
- **User**: identifier, organization_id, email, hashed credential (password hash or API key
  hash), role, status (active/inactive), failed_login_count, locked_until (nullable),
  created_at — belongs to exactly one organization.
- **AuditLogEntry**: identifier, occurred_at (UTC), user_id (nullable), organization_id
  (nullable), event_type (LOGIN_SUCCESS | LOGIN_FAILURE | LOGOUT | TOKEN_REFRESH), ip_address
  — append-only, never modified after creation.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A new user completes their first successful login and receives a usable access
  token within 3 interactive steps from a freshly created account.
- **SC-002**: An org admin performing user management tasks never receives data or errors
  that reference any other organization, verified across all user management operations.
- **SC-003**: Every authentication event produces an audit log entry visible to the org admin
  within 1 second of the event occurring.
- **SC-004**: Cross-tenant access attempts — using a valid token to access another
  organization's data — are rejected 100% of the time, verified by an automated test suite.
- **SC-005**: A super-admin creates a new organization and it is ready to accept its first
  user in under 2 minutes.
- **SC-006**: The initial deployment setup completes successfully in under 5 minutes on a
  fresh environment with no prior data.
- **SC-007**: Deactivating a user or organization takes effect for all new authentication
  attempts without a service restart or redeployment.

## Assumptions

- JWT (JSON Web Tokens) is the stateless token format signed with HS256 (HMAC-SHA256, single
  shared secret); this is sufficient for a single-service deployment and can be migrated to RS256
  via configuration if independent verification by other services is needed in future. Access
  tokens are short-lived (configurable, default 15 minutes) paired with longer-lived refresh
  tokens (configurable, default 7 days).
- Email addresses are the unique login identifier for human users.
- Service accounts authenticate via API keys; API keys are stored in hashed form and treated
  with the same security requirements as passwords.
- Password complexity rules are configurable via environment variables and not hardcoded.
- Password reset and self-service credential recovery are out of scope for v1.
- The audit log is append-only; no entry is ever deleted or modified after creation.
- Audit log write failures are non-blocking: if an audit write fails, the primary
  authentication operation still completes and the failure is logged to the application
  error log.
- Organization names are unique across the system.
- A role change takes effect on the user's next token issuance; existing valid tokens
  retain their embedded role until natural expiry.
- Refresh tokens rotate on every use; presenting an already-used refresh token is treated as
  a potential theft signal and invalidates the entire token family for that user session.
- The initial setup is triggered via a dedicated CLI command or a protected bootstrap
  endpoint, not the standard API surface.
- Multi-factor authentication (MFA) is out of scope for v1.
- The `super_admin` role is assigned directly in the database or via the CLI during operator
  setup; no API endpoint exists to grant or revoke `super_admin` from the standard UI.
- Account lockout thresholds (consecutive failure count, lockout duration) are configurable
  via environment variables; defaults are 5 attempts and 15 minutes.
- Access tokens embed a JTI (UUID). A revocation store (PostgreSQL table, indexed by JTI and
  expiry) holds JTIs of tokens that must be rejected before natural expiry. On user or
  organization deactivation, a sentinel record keyed to the user_id or organization_id is
  written so that all subsequently presented tokens for that subject are rejected. Revocation
  records are pruned once their associated token's natural expiry has passed.

## Clarifications

### Session 2026-07-04

- Q: How should stateless JWT verification (FR-003) be reconciled with the requirement to immediately deny deactivated users/organizations (FR-007, FR-011)? → A: Revocation blocklist — deactivation writes to a revocation store; every authenticated request checks it, ensuring instant effect without waiting for token expiry.
- Q: Should the spec define brute-force / rate-limiting protection on login attempts? → A: Account-based lockout (N consecutive failures locks account for configurable window; auto-clears; org admin can manually unlock; error responses are indistinguishable to prevent enumeration).
- Q: Which JWT signing algorithm should be used? → A: HS256 (HMAC-SHA256, single shared secret) — sufficient for current single-service deployment; migratable to RS256 via configuration if needed.
- Q: Should refresh tokens rotate on use? → A: Yes — rotate on every use; old token invalidated, new token issued; replaying a used token is treated as theft and invalidates the full session family.
- Q: Who can create service accounts and API keys? → A: Org admins only, scoped to their organization — mirrors existing user management model; API key shown once at creation, stored as hash thereafter.