"""Integration tests for Phase 3 (US2): initial deployment setup."""
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_setup_on_blank_db_succeeds(client: AsyncClient) -> None:
    """Scenario 1a: blank DB returns 201 with org + admin IDs."""
    response = await client.post(
        "/setup",
        json={
            "organization_name": "Acme Corp",
            "admin_email": "admin@acme.example",
            "admin_password": "S3cur3P@ssword!",
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["organization_name"] == "Acme Corp"
    assert "organization_id" in data
    assert "admin_user_id" in data


@pytest.mark.asyncio
async def test_setup_admin_can_login(client: AsyncClient) -> None:
    """Scenario 1b: admin created by setup can log in via POST /auth/login."""
    await client.post(
        "/setup",
        json={
            "organization_name": "Login Corp",
            "admin_email": "admin@login.example",
            "admin_password": "P@ssw0rd123!",
        },
    )

    login_response = await client.post(
        "/auth/login",
        json={
            "email": "admin@login.example",
            "password": "P@ssw0rd123!",
        },
    )
    assert login_response.status_code == 200
    tokens = login_response.json()
    assert "access_token" in tokens
    assert "refresh_token" in tokens


@pytest.mark.asyncio
async def test_second_setup_returns_409(client: AsyncClient) -> None:
    """Scenario 2: second setup call returns 409 with clear error message."""
    await client.post(
        "/setup",
        json={
            "organization_name": "First Corp",
            "admin_email": "first@corp.example",
            "admin_password": "F1rstP@ss!",
        },
    )

    response = await client.post(
        "/setup",
        json={
            "organization_name": "Second Corp",
            "admin_email": "second@corp.example",
            "admin_password": "S3condP@ss!",
        },
    )
    assert response.status_code == 409
    body = response.json()
    assert "detail" in body
    assert "already initialized" in body["detail"].lower()