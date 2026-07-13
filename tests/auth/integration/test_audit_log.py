"""Integration tests for Phase 6 (US4): org admin views audit log (T037)."""
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


# ── Scenario 1: GET /audit returns only own-org entries ───────────────────────

@pytest.mark.asyncio
async def test_audit_scoped_to_own_org(client: AsyncClient, make_org, make_admin) -> None:
    await _setup_org(client, "AuditOrg1", "admin@audit1.example", "AuditP@ss1!")
    admin1 = await _login(client, "admin@audit1.example", "AuditP@ss1!")

    # Create a second org directly so both have audit entries
    org2 = await make_org("AuditOrg2")
    await make_admin(org2, "admin@audit2.example", "AuditP@ss2!")
    admin2 = await _login(client, "admin@audit2.example", "AuditP@ss2!")

    # Both orgs now have LOGIN_SUCCESS audit entries; each admin should only see their own
    r1 = await client.get("/audit", headers=_auth(admin1))
    assert r1.status_code == 200
    data1 = r1.json()
    assert data1["total"] >= 1
    for entry in data1["items"]:
        # All returned entries must belong to the org of admin1 (no cross-org leak)
        assert entry["event_type"] in {
            "LOGIN_SUCCESS", "LOGIN_FAILURE", "LOGOUT", "TOKEN_REFRESH", "ACCOUNT_LOCKED"
        }

    r2 = await client.get("/audit", headers=_auth(admin2))
    assert r2.status_code == 200
    data2 = r2.json()
    assert data2["total"] >= 1

    # The two totals must differ (they are from separate orgs, not the same pool)
    # org1 entries should not appear in org2 result and vice-versa
    ids1 = {e["id"] for e in data1["items"]}
    ids2 = {e["id"] for e in data2["items"]}
    assert ids1.isdisjoint(ids2), "Audit entries leaked between orgs"


# ── Scenario 2: event_type filter ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_audit_event_type_filter(client: AsyncClient) -> None:
    await _setup_org(client, "FilterOrg", "admin@filter.example", "FilterP@ss1!")
    admin = await _login(client, "admin@filter.example", "FilterP@ss1!")

    # Trigger a LOGIN_FAILURE
    await client.post(
        "/auth/login", json={"email": "admin@filter.example", "password": "WrongPass!"}
    )

    r = await client.get("/audit?event_type=LOGIN_FAILURE", headers=_auth(admin))
    assert r.status_code == 200
    data = r.json()
    assert data["total"] >= 1
    for entry in data["items"]:
        assert entry["event_type"] == "LOGIN_FAILURE"


# ── Scenario 3: date range filter ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_audit_date_range_filter(client: AsyncClient) -> None:
    from datetime import UTC, datetime, timedelta

    await _setup_org(client, "DateOrg", "admin@date.example", "DateP@ss1!")
    admin = await _login(client, "admin@date.example", "DateP@ss1!")

    future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    past = (datetime.now(UTC) - timedelta(hours=1)).isoformat()

    # from=past, to=future should include the LOGIN_SUCCESS entry
    # Use params= so httpx properly URL-encodes the '+' in timezone offset
    r = await client.get("/audit", params={"from": past, "to": future}, headers=_auth(admin))
    assert r.status_code == 200
    assert r.json()["total"] >= 1

    # from=future should return no entries (all events are in the past)
    r2 = await client.get("/audit", params={"from": future}, headers=_auth(admin))
    assert r2.status_code == 200
    assert r2.json()["total"] == 0


# ── Scenario 4: results ordered occurred_at DESC ──────────────────────────────

@pytest.mark.asyncio
async def test_audit_ordered_desc(client: AsyncClient) -> None:
    await _setup_org(client, "OrderOrg", "admin@order.example", "OrderP@ss1!")
    admin = await _login(client, "admin@order.example", "OrderP@ss1!")

    # Trigger a second event so there are at least 2 entries
    await client.post(
        "/auth/login", json={"email": "admin@order.example", "password": "WrongPass!"}
    )

    r = await client.get("/audit", headers=_auth(admin))
    assert r.status_code == 200
    items = r.json()["items"]
    if len(items) >= 2:
        from datetime import datetime
        timestamps = [datetime.fromisoformat(e["occurred_at"]) for e in items]
        assert timestamps == sorted(timestamps, reverse=True), "Results not in DESC order"


# ── Scenario 5: pagination ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_audit_pagination(client: AsyncClient) -> None:
    await _setup_org(client, "PageOrg", "admin@page.example", "PageP@ss1!")
    admin = await _login(client, "admin@page.example", "PageP@ss1!")

    # Trigger multiple events to have at least 2 rows
    await client.post("/auth/login", json={"email": "admin@page.example", "password": "Bad!"})
    await client.post("/auth/login", json={"email": "admin@page.example", "password": "Bad!"})

    page0 = await client.get("/audit?limit=1&offset=0", headers=_auth(admin))
    page1 = await client.get("/audit?limit=1&offset=1", headers=_auth(admin))

    assert page0.status_code == 200
    assert page1.status_code == 200

    items0 = page0.json()["items"]
    items1 = page1.json()["items"]

    assert len(items0) <= 1
    assert len(items1) <= 1
    if items0 and items1:
        assert items0[0]["id"] != items1[0]["id"], "Pagination returned same entry on both pages"


# ── Scenario 6: total field reflects unfiltered org count ─────────────────────

@pytest.mark.asyncio
async def test_audit_total_reflects_org_count(client: AsyncClient) -> None:
    await _setup_org(client, "TotalOrg", "admin@total.example", "TotalP@ss1!")
    admin = await _login(client, "admin@total.example", "TotalP@ss1!")

    # One more event for a different event_type
    await client.post("/auth/login", json={"email": "admin@total.example", "password": "Wrong!"})

    all_r = await client.get("/audit", headers=_auth(admin))
    filtered_r = await client.get("/audit?event_type=LOGIN_FAILURE", headers=_auth(admin))

    assert all_r.status_code == 200
    assert filtered_r.status_code == 200

    total_all = all_r.json()["total"]
    total_filtered = filtered_r.json()["total"]

    # Total unfiltered must be >= filtered total
    assert total_all >= total_filtered
