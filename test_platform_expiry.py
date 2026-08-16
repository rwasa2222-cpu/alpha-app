"""
Tests for Task 21: token expiry capture in connect_platform.

Covers:
- Connecting with explicit token_expiry (ISO 8601) stores the correct datetime
- Connecting with expires_in stores now + expires_in seconds
- Connecting with neither stores the platform-specific default expiry
- token_expiry takes priority over expires_in when both are supplied
- Invalid token_expiry format returns 400
- Reconnecting (PUT-style via POST) updates the expiry
- token_status is reflected correctly in GET /api/v1/platforms

conftest.py patches models.SessionLocal to use an in-memory SQLite DB so
these tests never touch alpha.db and run reproducibly from a clean state.
"""

import uuid
import pyotp
import pytest
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient

from main import app, _PLATFORM_DEFAULT_EXPIRY_SECONDS

client = TestClient(app)

# ── helpers ───────────────────────────────────────────────────────────────────

def _unique_email() -> str:
    return f"user_{uuid.uuid4().hex[:8]}@test.com"


def register_and_login(password: str = "Pass123!") -> str:
    """Return a valid Bearer token."""
    email = _unique_email()
    reg = client.post("/api/v1/auth/register", json={"email": email, "password": password})
    assert reg.status_code == 201, reg.text
    totp_secret = reg.json()["two_fa_secret"]
    code = pyotp.TOTP(totp_secret).now()
    login = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password, "totp_code": code},
    )
    assert login.status_code == 200, login.text
    return login.json()["access_token"]


def auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def connect(token: str, platform: str = "instagram", **extra) -> dict:
    payload = {"access_token": "tok_test123", **extra}
    r = client.post(f"/api/v1/platforms/{platform}", json=payload, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


def get_platform_info(token: str, platform: str = "instagram") -> dict:
    r = client.get("/api/v1/platforms", headers=auth_headers(token))
    assert r.status_code == 200, r.text
    for p in r.json()["platforms"]:
        if p["platform"] == platform:
            return p
    raise AssertionError(f"Platform {platform} not found in response")


# ── token_expiry ISO 8601 ─────────────────────────────────────────────────────

def test_explicit_token_expiry_iso8601_stored():
    """Explicit token_expiry (ISO 8601 string) is stored verbatim on the row."""
    token = register_and_login()
    future = datetime.utcnow() + timedelta(days=30)
    iso = future.strftime("%Y-%m-%dT%H:%M:%S")

    connect(token, platform="instagram", token_expiry=iso)

    info = get_platform_info(token, "instagram")
    assert info["connected"] is True
    assert info["token_expiry"] is not None
    stored_expiry = datetime.fromisoformat(info["token_expiry"])
    # Allow a 5-second tolerance for any clock drift during the test
    assert abs((stored_expiry - future).total_seconds()) < 5


def test_explicit_token_expiry_with_z_suffix():
    """ISO 8601 timestamps with trailing 'Z' are accepted and stored."""
    token = register_and_login()
    future = datetime.utcnow() + timedelta(days=10)
    iso_z = future.strftime("%Y-%m-%dT%H:%M:%SZ")

    connect(token, platform="youtube", token_expiry=iso_z)

    info = get_platform_info(token, "youtube")
    assert info["token_expiry"] is not None


def test_invalid_token_expiry_returns_400():
    """A malformed token_expiry value must be rejected with HTTP 400."""
    token = register_and_login()
    r = client.post(
        "/api/v1/platforms/instagram",
        json={"access_token": "tok_abc", "token_expiry": "not-a-datetime"},
        headers=auth_headers(token),
    )
    assert r.status_code == 400
    assert "token_expiry" in r.json()["detail"].lower()


# ── expires_in (seconds) ──────────────────────────────────────────────────────

def test_expires_in_seconds_stored():
    """expires_in stores token_expiry as now + expires_in seconds."""
    token = register_and_login()
    before = datetime.utcnow()
    connect(token, platform="tiktok", expires_in=7200)
    after = datetime.utcnow()

    info = get_platform_info(token, "tiktok")
    assert info["token_expiry"] is not None
    stored = datetime.fromisoformat(info["token_expiry"])
    expected_low = before + timedelta(seconds=7200)
    expected_high = after + timedelta(seconds=7200)
    assert expected_low <= stored <= expected_high


# ── platform-specific defaults ────────────────────────────────────────────────

def test_no_expiry_fields_uses_platform_default_youtube():
    """YouTube default is 3 600 s (1 hour); stored expiry must be close to now+1h."""
    token = register_and_login()
    before = datetime.utcnow()
    connect(token, platform="youtube")
    after = datetime.utcnow()

    info = get_platform_info(token, "youtube")
    assert info["token_expiry"] is not None
    stored = datetime.fromisoformat(info["token_expiry"])
    default_s = _PLATFORM_DEFAULT_EXPIRY_SECONDS["youtube"]   # 3 600
    assert (before + timedelta(seconds=default_s)) <= stored <= (after + timedelta(seconds=default_s))


def test_no_expiry_fields_uses_platform_default_instagram():
    """Instagram default is 60 days (~5 184 000 s)."""
    token = register_and_login()
    before = datetime.utcnow()
    connect(token, platform="instagram")
    after = datetime.utcnow()

    info = get_platform_info(token, "instagram")
    assert info["token_expiry"] is not None
    stored = datetime.fromisoformat(info["token_expiry"])
    default_s = _PLATFORM_DEFAULT_EXPIRY_SECONDS["instagram"]
    assert (before + timedelta(seconds=default_s)) <= stored <= (after + timedelta(seconds=default_s))


# ── priority: token_expiry beats expires_in ───────────────────────────────────

def test_token_expiry_takes_priority_over_expires_in():
    """When both token_expiry and expires_in are supplied, token_expiry wins."""
    token = register_and_login()
    explicit_dt = datetime.utcnow() + timedelta(days=45)
    iso = explicit_dt.strftime("%Y-%m-%dT%H:%M:%S")

    # expires_in = 3600 (1 hour) should be ignored in favour of 45-day explicit expiry
    connect(token, platform="facebook", token_expiry=iso, expires_in=3600)

    info = get_platform_info(token, "facebook")
    stored = datetime.fromisoformat(info["token_expiry"])
    # Should be ~45 days away, not ~1 hour
    assert (stored - datetime.utcnow()).total_seconds() > timedelta(days=30).total_seconds()


# ── reconnect updates expiry ──────────────────────────────────────────────────

def test_reconnect_updates_expiry():
    """A second POST to the same platform overwrites the stored expiry."""
    token = register_and_login()

    # First connect: 1 hour default (youtube)
    connect(token, platform="youtube")
    info_first = get_platform_info(token, "youtube")

    # Reconnect with a 30-day explicit expiry
    future = datetime.utcnow() + timedelta(days=30)
    iso = future.strftime("%Y-%m-%dT%H:%M:%S")
    connect(token, platform="youtube", token_expiry=iso)

    info_second = get_platform_info(token, "youtube")
    stored_second = datetime.fromisoformat(info_second["token_expiry"])
    # New expiry should be roughly 30 days from now, well beyond the original 1-hour default
    assert (stored_second - datetime.utcnow()).total_seconds() > timedelta(days=29).total_seconds()


# ── token_status in list endpoint ─────────────────────────────────────────────

def test_token_status_ok_for_future_expiry():
    """A token expiring far in the future must report token_status='ok'."""
    token = register_and_login()
    future = datetime.utcnow() + timedelta(days=60)
    connect(token, platform="linkedin", token_expiry=future.strftime("%Y-%m-%dT%H:%M:%S"))

    info = get_platform_info(token, "linkedin")
    assert info["token_status"] == "ok"


def test_token_status_expiring_soon():
    """A token expiring within the next 7 days reports token_status='expiring_soon'."""
    token = register_and_login()
    soon = datetime.utcnow() + timedelta(days=3)
    connect(token, platform="threads", token_expiry=soon.strftime("%Y-%m-%dT%H:%M:%S"))

    info = get_platform_info(token, "threads")
    assert info["token_status"] == "expiring_soon"


def test_token_status_expired():
    """A token whose expiry is in the past reports token_status='expired'."""
    token = register_and_login()
    past = datetime.utcnow() - timedelta(hours=1)
    connect(token, platform="tiktok", token_expiry=past.strftime("%Y-%m-%dT%H:%M:%S"))

    info = get_platform_info(token, "tiktok")
    assert info["token_status"] == "expired"
