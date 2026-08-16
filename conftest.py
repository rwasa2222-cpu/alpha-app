"""
Pytest configuration: redirect all DB operations to a temporary SQLite file so
tests never touch alpha.db and always start from a clean state.

Sync routes  → models.SessionLocal is replaced with a StaticPool in-memory engine.
Async routes → database.get_async_db dependency is overridden via
               app.dependency_overrides to use a fresh aiosqlite temp-file engine.
               A temp file (not :memory:) is used for the async engine because
               aiosqlite's StaticPool doesn't survive event-loop hand-offs that
               happen inside Starlette's TestClient.

Rate limiter → disabled for every test so requests are never throttled.
"""

import asyncio
import os
import tempfile

import pytest
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Must be set before main.py is imported so _JWT_SECRET is not None.
os.environ.setdefault("SESSION_SECRET", "test-secret-at-least-32-chars-long!!")


# ── sync DB patch (legacy sync routes / models.get_db) ───────────────────────

@pytest.fixture(scope="session", autouse=True)
def _patch_sync_db():
    """Replace models.SessionLocal with a shared in-memory SQLite engine."""
    import models
    from models import Base

    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestSession = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    Base.metadata.create_all(bind=test_engine)

    orig_engine = models.engine
    orig_session = models.SessionLocal
    models.engine = test_engine
    models.SessionLocal = TestSession

    yield test_engine

    models.engine = orig_engine
    models.SessionLocal = orig_session
    Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()


# ── async DB patch (all async FastAPI routes via get_async_db) ───────────────

@pytest.fixture(scope="session", autouse=True)
def _patch_async_db(_patch_sync_db):
    """
    Override app.dependency_overrides[get_async_db] with a temp-file aiosqlite
    engine so async routes use SQLite instead of asyncpg during tests.
    """
    import database
    from main import app
    from models import Base

    # Temp file — aiosqlite works reliably across event loops with a real file.
    tmp = tempfile.NamedTemporaryFile(suffix=".test.db", delete=False)
    tmp.close()
    db_path = tmp.name

    async_test_engine = create_async_engine(
        f"sqlite+aiosqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    AsyncTestSession = async_sessionmaker(
        async_test_engine, expire_on_commit=False, class_=AsyncSession
    )

    # Create tables synchronously before the first test runs.
    async def _create():
        async with async_test_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    asyncio.run(_create())

    async def _get_test_db():
        async with AsyncTestSession() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[database.get_async_db] = _get_test_db

    # Also patch the module-level names so tests that call database.AsyncSessionLocal
    # directly (e.g. to back-date rows outside a request) hit the same test DB.
    orig_async_engine = database.async_engine
    orig_async_session = database.AsyncSessionLocal
    database.async_engine = async_test_engine
    database.AsyncSessionLocal = AsyncTestSession

    yield async_test_engine

    app.dependency_overrides.pop(database.get_async_db, None)
    database.async_engine = orig_async_engine
    database.AsyncSessionLocal = orig_async_session

    async def _dispose():
        await async_test_engine.dispose()

    asyncio.run(_dispose())
    try:
        os.unlink(db_path)
    except OSError:
        pass


# ── rate-limiter kill-switch ──────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _disable_rate_limits():
    """Disable slowapi rate limiting for every test so requests are never throttled."""
    from main import limiter
    limiter.enabled = False
    yield
    limiter.enabled = True
