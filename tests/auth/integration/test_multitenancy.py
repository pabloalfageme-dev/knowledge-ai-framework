"""SC-004 cross-tenant isolation tests (T041).

Creates Org A and Org B, each with an admin and a regular user.
All cross-tenant operations must return 403 or 404 — never 200.

db_session issues SET ROLE kn_app at the start of each test so these scenarios
verify DB-layer RLS enforcement, not just the application-layer WHERE clauses.
authenticate_user and refresh_tokens revert to kn_app (via set_app_context) after
the cross-org email/token lookup, so subsequent queries within the same test
transaction run under the tenant_isolation RLS policy.  A bug that removes the
WHERE organization_id clause from service.py would still be caught here.
"""
import pytest
from httpx import AsyncClient

# ── Helpers ───────────────────────────────────────────────────────────────────

async def _setup_org(client: AsyncClient, org: str, email: str, pw: str) -> dict:
    r = await client.post(
        "/setup",
        json={"organization_name": org, "admin_email": email, "admin_password": pw},
    )
    assert r.status_code == 201
    return r.json()


async def _login(client: AsyncClient, email: str, pw: str) -> dict:
    r = await client.post("/auth/login", json={"email": email, "password": pw})
    assert r.status_code == 200, r.text
    return r.json()


def _auth(tokens: dict) -> dict:
    return {"Authorization": f"Bearer {tokens['access_token']}"}


# ── Fixtures: two orgs, each with admin + user ────────────────────────────────

@pytest.fixture
async def two_orgs(client, make_org, make_admin, make_user):
    """Returns (org_a_admin_tokens, org_b_admin_tokens, org_b_user_id)."""
    # Org A via POST /setup (first call)
    await _setup_org(client, "TenantOrgA", "admin@tena.example", "TenA@Pass1!")
    admin_a = await _login(client, "admin@tena.example", "TenA@Pass1!")

    # Create user A via API (we are admin_a)
    r = await client.post(
        "/users",
        json={"email": "user@tena.example", "password": "TenA@User1!", "role": "user"},
        headers=_auth(admin_a),
    )
    assert r.status_code == 201

    # Org B directly via fixtures
    org_b = await make_org("TenantOrgB")
    await make_admin(org_b, "admin@tenb.example", "TenB@Pass1!")
    admin_b = await _login(client, "admin@tenb.example", "TenB@Pass1!")

    # Create user B via API
    r = await client.post(
        "/users",
        json={"email": "user@tenb.example", "password": "TenB@User1!", "role": "user"},
        headers=_auth(admin_b),
    )
    assert r.status_code == 201
    org_b_user_id = r.json()["id"]

    return admin_a, admin_b, org_b_user_id


# ── Test: GET /users returns only own-org users ───────────────────────────────

@pytest.mark.asyncio
async def test_list_users_scoped_to_own_org(client: AsyncClient, two_orgs) -> None:
    admin_a, admin_b, org_b_user_id = two_orgs

    r = await client.get("/users", headers=_auth(admin_a))
    assert r.status_code == 200
    user_ids = {u["id"] for u in r.json()}
    assert org_b_user_id not in user_ids, "Org B user appeared in Org A's /users response"


# ── Test: PATCH /users/{org_b_user_id} returns 404 for admin_a ───────────────

@pytest.mark.asyncio
async def test_cross_org_patch_returns_404(client: AsyncClient, two_orgs) -> None:
    admin_a, admin_b, org_b_user_id = two_orgs

    r = await client.patch(
        f"/users/{org_b_user_id}",
        json={"role": "admin"},
        headers=_auth(admin_a),
    )
    assert r.status_code == 404


# ── Test: POST /users creates user in own org only ────────────────────────────

@pytest.mark.asyncio
async def test_create_user_scoped_to_own_org(client: AsyncClient, two_orgs) -> None:
    admin_a, admin_b, org_b_user_id = two_orgs

    r = await client.post(
        "/users",
        json={"email": "newuser@tena.example", "password": "NewU@Pass1!", "role": "user"},
        headers=_auth(admin_a),
    )
    assert r.status_code == 201
    # Verify the new user is visible to admin_a's /users
    list_r = await client.get("/users", headers=_auth(admin_a))
    emails = {u["email"] for u in list_r.json()}
    assert "newuser@tena.example" in emails

    # Verify it is NOT visible to admin_b
    list_b = await client.get("/users", headers=_auth(admin_b))
    emails_b = {u["email"] for u in list_b.json()}
    assert "newuser@tena.example" not in emails_b


# ── Test: GET /audit returns only own-org entries ─────────────────────────────

@pytest.mark.asyncio
async def test_audit_scoped_to_own_org(client: AsyncClient, two_orgs) -> None:
    admin_a, admin_b, _ = two_orgs

    audit_a = await client.get("/audit", headers=_auth(admin_a))
    audit_b = await client.get("/audit", headers=_auth(admin_b))

    assert audit_a.status_code == 200
    assert audit_b.status_code == 200

    ids_a = {e["id"] for e in audit_a.json()["items"]}
    ids_b = {e["id"] for e in audit_b.json()["items"]}
    assert ids_a.isdisjoint(ids_b), "Audit log entries leaked between orgs"


# ── Test: unlock endpoint on cross-org user returns 404 ───────────────────────

@pytest.mark.asyncio
async def test_cross_org_unlock_returns_404(client: AsyncClient, two_orgs) -> None:
    admin_a, admin_b, org_b_user_id = two_orgs

    r = await client.post(
        f"/users/{org_b_user_id}/unlock",
        headers=_auth(admin_a),
    )
    assert r.status_code == 404
