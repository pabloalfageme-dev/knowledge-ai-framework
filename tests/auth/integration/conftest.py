"""Integration test fixtures.

Requires a live PostgreSQL instance. Set DATABASE_URL in the environment or a .env file.
Each test runs inside a transaction that is rolled back on teardown — no persistent state.
"""
import asyncio
from collections.abc import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.auth.models import Base
from src.core.config import settings
from src.core.database import get_db
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
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


# ── Session (function-scoped: autobegin + rollback after each test) ───────────

@pytest_asyncio.fixture
async def db_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    session_factory = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
    )
    async with session_factory() as session:
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