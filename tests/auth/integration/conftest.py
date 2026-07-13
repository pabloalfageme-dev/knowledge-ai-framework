"""Integration test fixtures.

Requires a live PostgreSQL instance. Set DATABASE_URL in the environment or a .env file.
Each test runs inside a transaction that is rolled back on teardown — no persistent state.
"""
import asyncio
from collections.abc import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.auth.models import Base, Organization, User
from src.auth.security import hash_password
from src.core.config import settings
from src.core.database import get_db, set_admin_context, set_rls_context
from src.main import app

# ── Engine (session-scoped: create tables once per test session) ─────────────


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session")
async def test_engine():
    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Create DB roles and RLS policies to mirror the production migration.
        # IF NOT EXISTS guards make this idempotent if roles already exist.
        for stmt in [
            """
            DO $$ BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kn_app') THEN
                    CREATE ROLE kn_app NOLOGIN;
                END IF;
            END $$;
            """,
            """
            DO $$ BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kn_admin') THEN
                    CREATE ROLE kn_admin NOLOGIN BYPASSRLS;
                END IF;
            END $$;
            """,
            "GRANT kn_admin TO kn_app;",
        ]:
            await conn.execute(text(stmt))
        for table in ("users", "audit_log", "refresh_tokens"):
            await conn.execute(text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
            await conn.execute(text(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))
            await conn.execute(
                text(
                    f"""
                    CREATE POLICY tenant_isolation ON {table}
                    AS PERMISSIVE FOR ALL TO kn_app
                    USING (organization_id = current_setting('app.current_org_id', true)::uuid)
                    WITH CHECK (organization_id = current_setting('app.current_org_id', true)::uuid)
                    """
                )
            )
        for table in ("organizations", "users", "audit_log", "refresh_tokens"):
            await conn.execute(
                text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO kn_app")
            )
            await conn.execute(
                text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO kn_admin")
            )
    yield engine
    async with engine.begin() as conn:
        # Connections acquired by db_session have SET ROLE kn_app (connection-level).
        # RESET ROLE reverts to the session authorization (postgres) so DDL ops succeed.
        await conn.execute(text("RESET ROLE"))
        for table in ("users", "audit_log", "refresh_tokens"):
            await conn.execute(text(f"DROP POLICY IF EXISTS tenant_isolation ON {table}"))
            await conn.execute(text(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY"))
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


# ── Session (function-scoped: autobegin + rollback after each test) ───────────


@pytest_asyncio.fixture
async def db_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    session_factory = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
    )
    async with session_factory() as session:
        # SET ROLE kn_app (connection-level, not LOCAL) so all queries in this test
        # run under the kn_app role and are subject to the tenant_isolation RLS policy.
        # This makes T041 cross-tenant tests meaningful: RLS blocks data leaks, not
        # just application-layer WHERE clauses. Service functions that need cross-org
        # access (login, token refresh, get_current_user) call set_admin_context()
        # locally and then revert with set_app_context() when done.
        await session.execute(text("SET ROLE kn_app"))
        # Patch commit → flush so handler commits don't escape the test transaction.
        # The fixture calls session.rollback() at teardown to undo all changes.
        session.commit = session.flush  # type: ignore[method-assign]
        yield session
        await session.rollback()


# ── HTTP client (uses the same session via dependency override) ───────────────


@pytest_asyncio.fixture
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


# ── Helper fixtures ───────────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def make_org(db_session: AsyncSession):
    async def _make(name: str = "Test Org") -> Organization:
        org = Organization(name=name)
        db_session.add(org)
        await db_session.flush()
        await db_session.refresh(org)
        return org

    return _make


@pytest_asyncio.fixture
async def make_user(db_session: AsyncSession):
    async def _make(
        org: Organization,
        email: str,
        password: str = "TestPass1!",
        role: str = "user",
    ) -> User:
        # WITH CHECK on users requires app.current_org_id = organization_id under kn_app.
        await set_rls_context(db_session, org.id)
        user = User(
            organization_id=org.id,
            email=email,
            credential_hash=hash_password(password),
            credential_type="password",
            role=role,
            status="active",
        )
        db_session.add(user)
        await db_session.flush()
        await db_session.refresh(user)
        return user

    return _make


@pytest_asyncio.fixture
async def make_admin(make_user):
    async def _make(org: Organization, email: str, password: str = "TestPass1!") -> User:
        return await make_user(org=org, email=email, password=password, role="admin")

    return _make


@pytest_asyncio.fixture
async def make_super_admin(db_session: AsyncSession):
    async def _make(email: str, password: str = "TestPass1!") -> User:
        # organization_id=None: RLS WITH CHECK (org_id = current_setting(...)) evaluates to
        # NULL = <uuid> → NULL (not TRUE) and rejects the INSERT under kn_app.
        # Escalate to kn_admin (BYPASSRLS) for this insert.
        # SET LOCAL ROLE is transaction-scoped: kn_admin applies for the rest of this test's
        # transaction, which is acceptable since super_admin test scenarios use kn_admin ops.
        await set_admin_context(db_session)
        user = User(
            organization_id=None,
            email=email,
            credential_hash=hash_password(password),
            credential_type="password",
            role="super_admin",
            status="active",
        )
        db_session.add(user)
        await db_session.flush()
        await db_session.refresh(user)
        return user

    return _make
