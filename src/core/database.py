import uuid
from collections.abc import AsyncGenerator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from src.core.config import settings

engine = create_async_engine(settings.DATABASE_URL, echo=False, pool_pre_ping=True)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def set_rls_context(session: AsyncSession, org_id: uuid.UUID | None) -> None:
    """Set the PostgreSQL session variable used by RLS policies.

    Must be called inside a transaction before any tenant-scoped query.
    """
    if org_id is not None:
        await session.execute(
            text("SET LOCAL app.current_org_id = :org_id"),
            {"org_id": str(org_id)},
        )


async def set_admin_context(session: AsyncSession) -> None:
    """Elevate the current transaction to the kn_admin role (BYPASSRLS).

    Use exclusively for cross-org super-admin operations (FR-012 aggregates,
    org lifecycle). kn_admin must be GRANTED to the login role in the migration.
    SET LOCAL scopes the role change to the current transaction only.
    """
    await session.execute(text("SET LOCAL ROLE kn_admin"))