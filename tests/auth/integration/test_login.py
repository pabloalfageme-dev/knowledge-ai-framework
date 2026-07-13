"""Integration tests for Phase 4 (US1): end-user login flow (T029)."""
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth.models import AuditLogEntry

# ── Helpers ───────────────────────────────────────────────────────────────────

async def _setup_org(client: AsyncClient, org_name: str, email: str, password: str) -> None:
    resp = await client.post(
        "/setup",
        json={"organization_name": org_name, "admin_email": email, "admin_password": password},
    )
    assert resp.status_code == 201


async def _login(client: AsyncClient, email: str, password: str) -> dict:
    resp = await client.post("/auth/login", json={"email": email, "password": password})
    return resp


# ── Scenario 1: valid login returns tokens + audit entry ─────────────────────

@pytest.mark.asyncio
async def test_valid_login_returns_token_pair(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _setup_org(client, "Acme", "admin@acme.example", "P@ssword1!")

    resp = await _login(client, "admin@acme.example", "P@ssword1!")
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] > 0

    result = await db_session.execute(
        select(AuditLogEntry).where(AuditLogEntry.event_type == "LOGIN_SUCCESS")
    )
    assert result.scalar_one_or_none() is not None


# ── Scenario 2: wrong password returns 401 + audit entry ─────────────────────

@pytest.mark.asyncio
async def test_wrong_password_returns_401_and_audit(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _setup_org(client, "BetaCorp", "admin@beta.example", "CorrectP@ss1!")

    resp = await _login(client, "admin@beta.example", "WrongPassword!")
    assert resp.status_code == 401

    result = await db_session.execute(
        select(AuditLogEntry).where(AuditLogEntry.event_type == "LOGIN_FAILURE")
    )
    assert result.scalar_one_or_none() is not None


# ── Scenario 3: deactivated user returns 401 ─────────────────────────────────

@pytest.mark.asyncio
async def test_deactivated_user_returns_401(client: AsyncClient, db_session: AsyncSession) -> None:
    await _setup_org(client, "GammaCorp", "admin@gamma.example", "P@ssword3!")

    from src.auth.models import User

    result = await db_session.execute(
        select(User).where(User.email == "admin@gamma.example")
    )
    user = result.scalar_one()
    user.status = "inactive"
    await db_session.flush()

    resp = await _login(client, "admin@gamma.example", "P@ssword3!")
    assert resp.status_code == 401


# ── Scenario 4: valid token grants access to a protected endpoint ─────────────

@pytest.mark.asyncio
async def test_valid_token_accesses_protected_endpoint(client: AsyncClient) -> None:
    await _setup_org(client, "DeltaCorp", "admin@delta.example", "P@ssword4!")

    login_resp = await _login(client, "admin@delta.example", "P@ssword4!")
    assert login_resp.status_code == 200
    tokens = login_resp.json()

    # Logout requires a valid Bearer token — proves the access token is accepted
    logout_resp = await client.post(
        "/auth/logout",
        json={"refresh_token": tokens["refresh_token"]},
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert logout_resp.status_code == 204


# ── Scenario 5: refresh issues new pair and invalidates old ──────────────────

@pytest.mark.asyncio
async def test_refresh_rotates_tokens(client: AsyncClient) -> None:
    await _setup_org(client, "EpsilonCorp", "admin@epsilon.example", "P@ssword5!")

    login_resp = await _login(client, "admin@epsilon.example", "P@ssword5!")
    tokens = login_resp.json()
    old_refresh = tokens["refresh_token"]

    refresh_resp = await client.post("/auth/refresh", json={"refresh_token": old_refresh})
    assert refresh_resp.status_code == 200
    new_tokens = refresh_resp.json()
    assert new_tokens["refresh_token"] != old_refresh
    assert "access_token" in new_tokens


# ── Scenario 6: refresh replay triggers 401 ───────────────────────────────────

@pytest.mark.asyncio
async def test_refresh_replay_returns_401(client: AsyncClient) -> None:
    await _setup_org(client, "ZetaCorp", "admin@zeta.example", "P@ssword6!")

    login_resp = await _login(client, "admin@zeta.example", "P@ssword6!")
    tokens = login_resp.json()
    refresh_token = tokens["refresh_token"]

    # First refresh succeeds
    first = await client.post("/auth/refresh", json={"refresh_token": refresh_token})
    assert first.status_code == 200

    # Replay of the same refresh token is rejected
    second = await client.post("/auth/refresh", json={"refresh_token": refresh_token})
    assert second.status_code == 401


# ── Scenario 7: logout returns 204 ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_logout_returns_204(client: AsyncClient) -> None:
    await _setup_org(client, "EtaCorp", "admin@eta.example", "P@ssword7!")

    login_resp = await _login(client, "admin@eta.example", "P@ssword7!")
    tokens = login_resp.json()

    logout_resp = await client.post(
        "/auth/logout",
        json={"refresh_token": tokens["refresh_token"]},
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert logout_resp.status_code == 204
