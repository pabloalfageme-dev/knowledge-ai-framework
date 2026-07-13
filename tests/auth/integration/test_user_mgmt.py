"""Integration tests for Phase 5 (US3): organization admin manages users (T034)."""
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


# ── Scenario 1: create user who can log in ────────────────────────────────────

@pytest.mark.asyncio
async def test_create_user_who_can_login(client: AsyncClient) -> None:
    await _setup_org(client, "Alpha", "admin@alpha.test", "AdminP@ss1!")
    admin = await _login(client, "admin@alpha.test", "AdminP@ss1!")

    r = await client.post(
        "/users",
        json={"email": "user1@alpha.test", "password": "UserP@ss1!", "role": "user"},
        headers=_auth(admin),
    )
    assert r.status_code == 201
    data = r.json()
    assert data["email"] == "user1@alpha.test"
    assert data["role"] == "user"
    assert data["status"] == "active"

    # New user can log in immediately
    user_tokens = await _login(client, "user1@alpha.test", "UserP@ss1!")
    assert "access_token" in user_tokens


# ── Scenario 2: deactivate user → login fails ────────────────────────────────

@pytest.mark.asyncio
async def test_deactivate_user_blocks_login(client: AsyncClient) -> None:
    await _setup_org(client, "Beta", "admin@beta2.test", "AdminP@ss2!")
    admin = await _login(client, "admin@beta2.test", "AdminP@ss2!")

    # Create user
    r = await client.post(
        "/users",
        json={"email": "user2@beta2.test", "password": "UserP@ss2!", "role": "user"},
        headers=_auth(admin),
    )
    assert r.status_code == 201
    user_id = r.json()["id"]

    # Verify user can log in
    await _login(client, "user2@beta2.test", "UserP@ss2!")

    # Deactivate the user
    r = await client.patch(
        f"/users/{user_id}",
        json={"status": "inactive"},
        headers=_auth(admin),
    )
    assert r.status_code == 200
    assert r.json()["status"] == "inactive"

    # Deactivated user cannot log in
    r = await client.post(
        "/auth/login",
        json={"email": "user2@beta2.test", "password": "UserP@ss2!"},
    )
    assert r.status_code == 401


# ── Scenario 3: cross-org action rejected (404) ───────────────────────────────

@pytest.mark.asyncio
async def test_cross_org_action_rejected(client: AsyncClient) -> None:
    await _setup_org(client, "Gamma1", "admin@gamma1.test", "AdminP@ss3!")
    await _setup_org(client, "Gamma2", "admin@gamma2.test", "AdminP@ss4!")

    admin1 = await _login(client, "admin@gamma1.test", "AdminP@ss3!")

    # Get a user_id from org2 — we need to create one first via admin2
    admin2 = await _login(client, "admin@gamma2.test", "AdminP@ss4!")
    r = await client.post(
        "/users",
        json={"email": "victim@gamma2.test", "password": "VictimP@ss!", "role": "user"},
        headers=_auth(admin2),
    )
    assert r.status_code == 201
    org2_user_id = r.json()["id"]

    # Admin1 tries to patch a user from org2 → 404 (not 403, to avoid org enumeration)
    r = await client.patch(
        f"/users/{org2_user_id}",
        json={"role": "admin"},
        headers=_auth(admin1),
    )
    assert r.status_code == 404


# ── Scenario 4: role change reflected in next token ──────────────────────────

@pytest.mark.asyncio
async def test_role_change_reflected_in_next_token(client: AsyncClient) -> None:
    await _setup_org(client, "Delta", "admin@delta2.test", "AdminP@ss5!")
    admin = await _login(client, "admin@delta2.test", "AdminP@ss5!")

    # Create a plain user
    r = await client.post(
        "/users",
        json={"email": "promoted@delta2.test", "password": "UserP@ss5!", "role": "user"},
        headers=_auth(admin),
    )
    user_id = r.json()["id"]

    # Promote to admin
    r = await client.patch(
        f"/users/{user_id}",
        json={"role": "admin"},
        headers=_auth(admin),
    )
    assert r.status_code == 200
    assert r.json()["role"] == "admin"

    # New login issues a token with updated role
    new_tokens = await _login(client, "promoted@delta2.test", "UserP@ss5!")

    # The new token should work with admin-only endpoints
    r = await client.get("/users", headers=_auth(new_tokens))
    assert r.status_code == 200


# ── Scenario 5: create service account → login with API key ──────────────────

@pytest.mark.asyncio
async def test_service_account_login_with_api_key(client: AsyncClient) -> None:
    await _setup_org(client, "Epsilon", "admin@epsilon2.test", "AdminP@ss6!")
    admin = await _login(client, "admin@epsilon2.test", "AdminP@ss6!")

    r = await client.post(
        "/service-accounts",
        json={"email": "svc@epsilon2.test", "role": "user"},
        headers=_auth(admin),
    )
    assert r.status_code == 201
    sa_data = r.json()
    assert "api_key" in sa_data
    raw_api_key = sa_data["api_key"]

    # Service account logs in using the raw API key as its password
    r = await client.post(
        "/auth/login",
        json={"email": "svc@epsilon2.test", "password": raw_api_key},
    )
    assert r.status_code == 200
    assert "access_token" in r.json()