import os
from sqlalchemy import (
    Column, Integer, String, Float, DateTime, Text, Boolean, Numeric,
    UniqueConstraint, create_engine,
)
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime
from typing import Optional

# ── Database URL ──────────────────────────────────────────────────────────────
# Set DATABASE_URL to a postgres:// or postgresql:// connection string in
# production (e.g. Supabase, Neon, Cloud SQL).  Falls back to SQLite for dev.
_raw_db_url = os.environ.get("DATABASE_URL", "sqlite:///./alpha.db")
# Heroku/Render emit "postgres://" which SQLAlchemy 1.4+ requires as "postgresql://"
DATABASE_URL = (
    _raw_db_url.replace("postgres://", "postgresql://", 1)
    if _raw_db_url.startswith("postgres://")
    else _raw_db_url
)

_IS_SQLITE = DATABASE_URL.startswith("sqlite")

if _IS_SQLITE:
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_size=5, max_overflow=10)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ── Models ────────────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    totp_secret = Column(String, nullable=False)
    # Extended profile fields (added in schema v2)
    package_tier = Column(String, default="starter")          # starter | creator_pro | business_automator | agency_master | enterprise
    onboarding_complete = Column(Boolean, default=False)
    content_schedule_time = Column(String, default="09:00:00")  # HH:MM:SS local time
    review_buffer_minutes = Column(Integer, default=15)
    is_business_mode = Column(Boolean, default=False)
    brand_name = Column(String, nullable=True)
    brand_contact = Column(String, nullable=True)
    brand_logo_url = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class UserWallet(Base):
    __tablename__ = "user_wallets"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, unique=True, index=True, nullable=False)
    available_balance = Column(Numeric(12, 2), default=0.00, nullable=False)
    pending_balance = Column(Numeric(12, 2), default=0.00, nullable=False)
    stripe_connect_id = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class UserAestheticSetting(Base):
    __tablename__ = "user_aesthetic_settings"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, unique=True, index=True, nullable=False)
    brand_name = Column(String, nullable=True)
    brand_contact = Column(String, nullable=True)
    hex_colors = Column(String, default="[]")           # JSON-encoded list
    header_font = Column(String, nullable=True)
    caption_font = Column(String, nullable=True)
    visual_podcast_template = Column(String, default="minimalist")  # minimalist | kinetic_pop | split_screen
    text_overlay_opacity = Column(Float, default=0.85)
    persistent_hashtags = Column(String, default="")
    active_target_language = Column(String, default="en")
    media_mix_video_percentage = Column(Integer, default=50)        # 0–100
    chosen_niche = Column(String, nullable=True)
    celebrity_tracker_string = Column(String, nullable=True)        # comma-separated legacy field
    delivery_time = Column(String, nullable=True)
    timezone = Column(String, default="UTC")
    auto_create_podcast_series = Column(Integer, default=0)         # boolean as int
    voice_id = Column(String, nullable=True)
    image_mode = Column(String, default="ai_generation")
    target_aspect_ratio = Column(String, default="9:16")   # "1:1" | "9:16"
    created_at = Column(DateTime, default=datetime.utcnow)


class UserSelectedSource(Base):
    """One row per niche/celebrity tracking chip the user has added.

    Replaces the legacy comma-separated ``celebrity_tracker_string`` field for
    multi-value tracking.  The old field is kept for backward-compat reads.
    """
    __tablename__ = "user_selected_sources"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True, nullable=False)
    chosen_niche = Column(String, nullable=True)
    celebrity_name = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class PostsQueue(Base):
    __tablename__ = "posts_queue"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True, nullable=False)
    episode_title = Column(String, nullable=True)
    content_text = Column(String, nullable=True)
    graphic_card_url = Column(String, nullable=True)
    voice_audio_url = Column(String, nullable=True)
    media_type = Column(String, default="image_card")   # image_card | automated_short_video
    status = Column(String, default="pending_review")   # pending_review | published | cancelled | failed
    scheduled_publish_time = Column(DateTime, nullable=True)
    publish_log = Column(Text, nullable=True)            # JSON per-platform publish results
    platform_target_list = Column(Text, nullable=True)  # JSON list of target platform names
    created_at = Column(DateTime, default=datetime.utcnow)


class Advertisement(Base):
    """Sponsor/ad contracts woven into generated script narrations."""
    __tablename__ = "advertisements"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True, nullable=False)
    sponsor_name = Column(String, nullable=True)
    sponsor_logo_url = Column(String, nullable=True)
    sponsor_contact = Column(String, nullable=True)
    sponsor_services_text = Column(Text, nullable=True)
    start_date = Column(DateTime, nullable=True)
    end_date = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class RevokedToken(Base):
    """Blacklist of revoked JWT IDs (JTIs). Checked on every authenticated request."""
    __tablename__ = "revoked_tokens"

    id = Column(Integer, primary_key=True, index=True)
    jti = Column(String, unique=True, index=True, nullable=False)
    user_id = Column(Integer, index=True, nullable=False)
    revoked_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)


class RecoveryCode(Base):
    """Single-use backup codes for 2FA device loss recovery."""
    __tablename__ = "recovery_codes"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True, nullable=False)
    code_hash = Column(String, nullable=False)
    used_at = Column(DateTime, nullable=True, default=None)
    created_at = Column(DateTime, default=datetime.utcnow)


class LoginOTP(Base):
    """6-digit email OTP generated fresh on every login attempt. Expires in 10 minutes."""
    __tablename__ = "login_otps"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True, nullable=False)
    code_hash = Column(String, nullable=False)   # bcrypt hash of the 6-digit code
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class PlatformToken(Base):
    """Per-user OAuth tokens for each connected social platform.

    ``access_token`` and ``refresh_token`` are stored AES-256-GCM encrypted.
    Use ``crypto.decrypt_token()`` before passing to any API call.
    """
    __tablename__ = "platform_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True, nullable=False)
    platform = Column(String, nullable=False)
    access_token = Column(Text, nullable=False)          # AES-256-GCM encrypted
    refresh_token = Column(Text, nullable=True)          # AES-256-GCM encrypted
    account_id = Column(String, nullable=True)
    platform_account_handle = Column(String, nullable=True)
    platform_user_id = Column(String, nullable=True)
    authorized_scopes = Column(Text, nullable=True)      # JSON array of granted scopes
    auto_publish_enabled = Column(Boolean, default=True)
    extra_data = Column(Text, default="{}")
    token_expiry = Column(DateTime, nullable=True)
    connected_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("user_id", "platform", name="uq_user_platform"),
    )


class OAuthState(Base):
    """Short-lived CSRF-protection nonces for OAuth2 handshakes.

    Each ``GET /api/v1/auth/connect/:platform`` call mints one row.
    The callback verifies the incoming ``state`` parameter against this table
    before exchanging the code for tokens, then deletes the row.
    """
    __tablename__ = "oauth_states"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True, nullable=False)
    platform = Column(String, nullable=False)
    state_nonce = Column(String, unique=True, index=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)   # TTL enforced in code (10 min)


# ── Schema initialisation & migrations ───────────────────────────────────────

def _col_names(inspector, table_name: str) -> list[str]:
    try:
        return [c["name"] for c in inspector.get_columns(table_name)]
    except Exception:
        return []


def _add_col_if_missing(conn, inspector, table: str, col: str, definition: str):
    if col not in _col_names(inspector, table):
        from sqlalchemy import text
        conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {definition}"))
        conn.commit()


def init_db():
    from sqlalchemy import inspect, text

    Base.metadata.create_all(bind=engine)

    inspector = inspect(engine)

    _MIGRATIONS: dict[str, list[tuple[str, str]]] = {
        "users": [
            ("package_tier",            "TEXT DEFAULT 'starter'"),
            ("onboarding_complete",     "BOOLEAN DEFAULT FALSE"),
            ("content_schedule_time",   "TEXT DEFAULT '09:00:00'"),
            ("review_buffer_minutes",   "INTEGER DEFAULT 15"),
            ("is_business_mode",        "BOOLEAN DEFAULT FALSE"),
            ("brand_name",              "TEXT"),
            ("brand_contact",           "TEXT"),
            ("brand_logo_url",          "TEXT"),
        ],
        "user_wallets": [
            ("pending_balance",         "REAL DEFAULT 0.0"),
            ("stripe_connect_id",       "TEXT"),
        ],
        "platform_tokens": [
            ("token_expiry",            "TIMESTAMP"),
            ("platform_account_handle", "TEXT"),
            ("platform_user_id",        "TEXT"),
            ("authorized_scopes",       "TEXT"),
            ("auto_publish_enabled",    "BOOLEAN DEFAULT TRUE"),
        ],
        "posts_queue": [
            ("publish_log",             "TEXT"),
            ("media_type",              "TEXT DEFAULT 'image_card'"),
            ("platform_target_list",    "TEXT"),
        ],
        "user_aesthetic_settings": [
            ("text_overlay_opacity",        "REAL DEFAULT 0.85"),
            ("media_mix_video_percentage",  "INTEGER DEFAULT 50"),
            ("target_aspect_ratio",         "TEXT DEFAULT '9:16'"),
        ],
    }

    with engine.connect() as conn:
        for table, cols in _MIGRATIONS.items():
            if inspector.has_table(table):
                for col, defn in cols:
                    _add_col_if_missing(conn, inspector, table, col, defn)

        # Ensure tables added after initial deployment exist
        for tbl in ("revoked_tokens", "recovery_codes", "oauth_states",
                    "user_selected_sources", "advertisements"):
            if not inspector.has_table(tbl):
                Base.metadata.tables[tbl].create(bind=engine, checkfirst=True)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
