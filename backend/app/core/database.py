"""Database session and engine initialization for EvidenceShield AI."""

from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import sessionmaker

from .config import settings
from ..models.entities import Base

# Async engine for FastAPI route handlers
async_engine = create_async_engine(
    settings.database_url,
    echo=False,
    future=True,
)

AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

# Sync engine for Alembic and worker scripts
sync_engine = create_engine(
    settings.database_sync_url,
    echo=False,
    future=True,
)

SyncSessionLocal = sessionmaker(
    bind=sync_engine,
    autocommit=False,
    autoflush=False,
)


async def get_db():
    """FastAPI dependency yielding async session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db():
    """Initializes tables for development/testing."""
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
