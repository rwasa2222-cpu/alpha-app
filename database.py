"""Async SQLAlchemy database layer — production PostgreSQL (asyncpg) / dev SQLite (aiosqlite).

This module sits on top of the sync model definitions in ``models.py`` and adds
a fully async connection pool, ``AsyncSession`` factory, and FastAPI dependency.

Exports
-------
async_engine        SQLAlchemy AsyncEngine (asyncpg or aiosqlite)
AsyncSessionLocal   async_sessionmaker producing AsyncSession instances
get_async_db()      FastAPI dependency — yields an AsyncSession, commits on exit
init_async_db()     coroutine — call once at startup to create all tables
ping_db()           async health check — returns True if DB is reachable
close_db()          async engine disposal — call on shutdown

Usage in a FastAPI route
------------------------
    from database import get_async_db
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy import select

    @app.get("/items")
    async def list_items(db: AsyncSession = Depends(get_async_db)):
        result = await db.execute(select(MyModel))
        return result.scalars().all()

Environment variables
---------------------
DATABASE_URL   Full connection string.  Supported schemes:
                 postgresql://user:pass@host:5432/dbname     → asyncpg pool
                 postgres://...                               → normalised → postgresql+asyncpg
                 sqlite:///./alpha.db                         → aiosqlite (dev only)
               Defaults to sqlite:///./alpha.db when unset.

               libpq query parameters (sslmode, sslrootcert, sslcert, sslkey,
               connect_timeout, application_name, keepalives …) are translated
               to asyncpg-compatible connect arguments and stripped from the URL
               so asyncpg never receives unknown keyword arguments.
"""

from __future__ import annotations

import os
import ssl
import logging
import warnings
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    AsyncEngine,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

# Re-use the declarative Base (and therefore all table metadata) from models.py
# so there is exactly one source of truth for schema definitions.
from models import Base, DATABASE_URL as _SYNC_URL

logger = logging.getLogger("alpha.database")

# ── libpq param groups ────────────────────────────────────────────────────────

_LIBPQ_SSL_PARAMS = frozenset({
    "sslmode", "sslcert", "sslkey", "sslrootcert",
    "sslcrl", "sslpassword", "sslcompression",
})

# libpq params with no asyncpg equivalent — dropped with a warning
_LIBPQ_DROP_PARAMS = frozenset({
    "keepalives", "keepalives_idle", "keepalives_interval", "keepalives_count",
    "tcp_user_timeout", "target_session_attrs", "load_balance_hosts",
    "gssencmode", "krbsrvname", "gsslib", "channel_binding",
    "service", "passfile", "options",
})

# libpq params that are translated to connect_args / server_settings
_LIBPQ_TRANSLATE_PARAMS = frozenset({
    "connect_timeout",   # → connect_args["timeout"]
    "application_name",  # → connect_args["server_settings"]["application_name"]
})

_ALL_LIBPQ_STRIP = _LIBPQ_SSL_PARAMS | _LIBPQ_DROP_PARAMS | _LIBPQ_TRANSLATE_PARAMS


# ── SSL context builder ───────────────────────────────────────────────────────

def _build_ssl_context(ssl_params: dict[str, str]) -> "ssl.SSLContext | bool | None":
    """Translate libpq SSL params to an asyncpg-compatible ssl argument.

    Returns:
        False           — sslmode=disable; no TLS.
        ssl.SSLContext  — encrypted connection with appropriate verification.
        None            — sslmode=prefer/allow or absent; asyncpg decides.
    """
    sslmode = ssl_params.get("sslmode", "prefer")

    if sslmode == "disable":
        return False

    if sslmode not in ("require", "verify-ca", "verify-full", "prefer", "allow"):
        sslmode = "prefer"

    needs_context = (
        sslmode in ("require", "verify-ca", "verify-full")
        or any(k in ssl_params for k in ("sslrootcert", "sslcert", "sslkey"))
    )
    if not needs_context:
        return None

    if sslmode == "verify-full":
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
    elif sslmode == "verify-ca":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        # require or prefer/allow with cert files: encrypt, skip server cert verify
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    sslrootcert = ssl_params.get("sslrootcert")
    if sslrootcert:
        ctx.load_verify_locations(cafile=sslrootcert)

    sslcert = ssl_params.get("sslcert")
    sslkey = ssl_params.get("sslkey")
    if sslcert and sslkey:
        ctx.load_cert_chain(
            certfile=sslcert,
            keyfile=sslkey,
            password=ssl_params.get("sslpassword"),
        )
    elif sslcert or sslkey:
        warnings.warn(
            "Both sslcert and sslkey must be supplied together for client-certificate "
            "authentication; the incomplete pair has been ignored.",
            stacklevel=2,
        )

    return ctx


# ── URL + connect-args derivation ─────────────────────────────────────────────

def _to_async_url(sync_url: str) -> tuple[str, dict]:
    """Convert a sync SQLAlchemy URL to the matching async dialect.

    Returns (async_url, connect_args).

    All libpq query parameters that asyncpg does not support are stripped from
    the URL.  SSL params are translated to an ssl.SSLContext (or bool).
    connect_timeout is translated to asyncpg's timeout.
    application_name is passed via server_settings.
    Unsupported libpq params are dropped with a warning.
    """
    url = sync_url

    # Handle SQLite before urlparse: sqlite:/// uses a non-standard triple-slash
    # that urlunparse collapses to single-slash on round-trip.
    if url.startswith("sqlite:///"):
        return url.replace("sqlite:///", "sqlite+aiosqlite:///", 1), {}

    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)

    parsed = urlparse(url)
    scheme = parsed.scheme

    query_params = parse_qs(parsed.query, keep_blank_values=True)

    ssl_raw = {k: v[0] for k, v in query_params.items() if k in _LIBPQ_SSL_PARAMS}
    translate_raw = {k: v[0] for k, v in query_params.items() if k in _LIBPQ_TRANSLATE_PARAMS}
    drop_raw = {k for k in query_params if k in _LIBPQ_DROP_PARAMS}
    clean_params = {k: v for k, v in query_params.items() if k not in _ALL_LIBPQ_STRIP}

    if drop_raw:
        warnings.warn(
            f"The following libpq URL parameters are not supported by asyncpg and "
            f"have been removed: {', '.join(sorted(drop_raw))}.",
            stacklevel=2,
        )

    new_query = urlencode({k: v[0] for k, v in clean_params.items()})
    clean_url = urlunparse(parsed._replace(query=new_query))

    connect_args: dict = {}

    # SSL
    ssl_value = _build_ssl_context(ssl_raw)
    if ssl_value is not None:
        connect_args["ssl"] = ssl_value

    # connect_timeout → asyncpg timeout (seconds)
    if "connect_timeout" in translate_raw:
        try:
            connect_args["timeout"] = float(translate_raw["connect_timeout"])
        except ValueError:
            warnings.warn(
                f"connect_timeout value '{translate_raw['connect_timeout']}' "
                "is not a valid number; ignored.",
                stacklevel=2,
            )

    # application_name → server_settings
    if "application_name" in translate_raw:
        connect_args.setdefault("server_settings", {})
        connect_args["server_settings"]["application_name"] = translate_raw["application_name"]

    # Swap sync dialect for async dialect
    if scheme in ("postgresql", "postgres"):
        async_url = clean_url.replace(f"{scheme}://", "postgresql+asyncpg://", 1)
    elif scheme == "sqlite":
        async_url = clean_url.replace("sqlite:///", "sqlite+aiosqlite:///", 1)
    else:
        async_url = clean_url  # already has async dialect or unknown

    return async_url, connect_args


ASYNC_DATABASE_URL, _connect_args = _to_async_url(_SYNC_URL)

# Alias kept for backwards compatibility (internal tests may reference either name)
_EXTRA_CONNECT_ARGS = _connect_args

# ── Engine factory ────────────────────────────────────────────────────────────

def _build_engine() -> AsyncEngine:
    is_pg = "asyncpg" in ASYNC_DATABASE_URL
    _echo = os.environ.get("SQL_ECHO", "").lower() in ("1", "true")

    if is_pg:
        engine = create_async_engine(
            ASYNC_DATABASE_URL,
            connect_args=_connect_args,
            pool_pre_ping=True,
            pool_size=5,
            max_overflow=10,
            pool_timeout=30,
            pool_recycle=1800,
            echo=_echo,
        )
    else:
        # SQLite+aiosqlite — NullPool avoids "closed database" errors in async
        engine = create_async_engine(
            ASYNC_DATABASE_URL,
            connect_args={"check_same_thread": False, **_connect_args},
            poolclass=NullPool,
            echo=_echo,
        )

    logger.info(
        "[DB] Async engine ready — dialect: %s",
        "PostgreSQL+asyncpg" if is_pg else "SQLite+aiosqlite",
    )
    return engine


async_engine: AsyncEngine = _build_engine()

# ── Session factory ───────────────────────────────────────────────────────────

AsyncSessionLocal: async_sessionmaker[AsyncSession] = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=True,
    autocommit=False,
)

# ── FastAPI dependency ────────────────────────────────────────────────────────


async def get_async_db() -> AsyncSession:  # type: ignore[return]
    """Yield an ``AsyncSession``, auto-commit on clean exit, rollback on error.

    Usage::

        @app.get("/things")
        async def read_things(db: AsyncSession = Depends(get_async_db)):
            ...
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# ── Schema initialisation ─────────────────────────────────────────────────────


async def init_async_db() -> None:
    """Create all tables defined in ``Base.metadata`` if they do not yet exist.

    Safe to call on every startup — ``create_all`` is idempotent for existing
    tables.  Column additions still require the migration logic in
    ``models.init_db()``; call both on startup when running against a
    pre-existing database.
    """
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("[DB] Async schema initialised (create_all completed).")


# ── Connection pool helpers ───────────────────────────────────────────────────


async def ping_db() -> bool:
    """Return True if the database is reachable, False otherwise.

    Suitable for a ``/health`` endpoint.
    """
    from sqlalchemy import text
    try:
        async with async_engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"[DB] Health ping failed: {exc}")
        return False


async def close_db() -> None:
    """Dispose the async engine connection pool.

    Call inside the FastAPI lifespan shutdown hook.
    """
    await async_engine.dispose()
    logger.info("[DB] Async connection pool disposed.")
