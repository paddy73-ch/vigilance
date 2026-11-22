from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import event
from sqlalchemy.pool import NullPool
from vigilance.config import settings


class Base(DeclarativeBase):
    pass


def _create_engine():
    """Create async engine with appropriate pool and settings for the database type."""
    url = settings.database_url
    is_sqlite = url.startswith("sqlite+aiosqlite://")
    is_postgres = url.startswith("postgresql+asyncpg://")

    if is_sqlite:
        # SQLite: use NullPool to avoid locking issues, apply WAL pragmas
        engine = create_async_engine(
            url,
            echo=settings.log_level == "DEBUG",
            future=True,
            poolclass=NullPool,
        )

        @event.listens_for(engine.sync_engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA busy_timeout=30000")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    elif is_postgres:
        # PostgreSQL: use default async pool (AsyncAdaptedQueuePool) with appropriate sizing
        engine = create_async_engine(
            url,
            echo=settings.log_level == "DEBUG",
            future=True,
            pool_size=5,
            max_overflow=10,
            pool_pre_ping=True,
            pool_recycle=3600,
        )
    else:
        raise ValueError(f"Unsupported database URL scheme: {url}")

    return engine


engine = _create_engine()

async_session_maker = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db():
    await engine.dispose()