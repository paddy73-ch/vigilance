import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

from vigilance.database.base import Base
from vigilance.database import crud
from vigilance.config import settings


@pytest.fixture(scope="session")
def event_loop():
    import asyncio
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="function")
async def db_engine():
    """Create an in-memory SQLite database for testing."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def db_session(db_engine):
    """Create a database session for testing."""
    async_session = async_sessionmaker(db_engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as session:
        yield session


@pytest.fixture
def sample_proxmox_node():
    return {
        "name": "test-node",
        "url": "https://proxmox.example.com:8006",
        "token_id": "vigilance@pam",
        "token_secret": "secret",
        "verify_tls": True,
    }


@pytest.fixture
def sample_inventory():
    return {
        "proxmox_node_id": 1,
        "vmid": 100,
        "name": "test-vm",
        "type": "qemu",
        "status": "running",
        "ip_address": "192.168.1.100",
        "hostname": "test-vm.local",
    }


@pytest.fixture
def sample_tool():
    return {
        "inventory_id": 1,
        "source_type": "ssh_pkg",
        "tool_name": "nginx",
        "detected_version": "1.18.0",
        "package_manager": "dpkg",
    }