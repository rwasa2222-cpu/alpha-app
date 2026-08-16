"""
Auth test suite — covers the full 2-step email-OTP login flow plus
registration, token validity, and protected-route enforcement.

Login flow (as of email-OTP refactor):
  Step 1  POST /api/v1/auth/login          → {status: 'code_sent', email: masked}
  Step 2  POST /api/v1/auth/login/verify   → {access_token, token_type, user_id}

conftest.py handles:
  - In-memory SQLite patch for both sync and async routes
  - Rate-limiter disabled for every test
  - SESSION_SECRET pre-set
"""

import uuid
import pytest
from unittest.mock import AsyncMock, patch
from jose import jwt
from fastapi.testclient import TestClient

from main import app, _JWT_SECRET, _JWT_ALGORITHM

client = TestClient(app)


# ── helpers ───────────────────────────────────────────────────────────────────

def _unique_email() -> str:
    return f"user_{uuid.uuid4().hex[:8]}@test.com"


def _register(email: str | None = None, password: str = "Pass123!") -> dict:
    """Register a new user, return the full response JSON."""
    email = email or _unique_email()
    r = client.post("/api/v1/auth/register", json={"email": email, "password": password})
    assert r.status_code == 201, r.text
    return {**r.json(), "email": email, "password": password}


def _login_step1(email: str, password: str) -> tuple[dict, str]:
    """
    POST /api/v1/auth/login with _send_otp_email patched to capture the code.
    Returns (step1_response_json, captured_otp_code).
    """
    captured: dict = {}

    async def _fake_send(to_email: str, otp_code: str) -> None:
        captured["otp"] = otp_code

    with patch("main._send_otp_email", side_effect=_fake_send):
        r = client.post("/api/v1/auth/login", json={"email": email, "password": password})

    return r, captured.get("otp", "")


def register_and_login(email: str | None = None, password: str = "Pass123!") -> tuple[str, int]:
    """
    Full registration + 2-step email-OTP login.
    Returns (access_token, user_id).
    """
    info = _register(email, password)
    step1, otp_code = _login_step1(info["email"], info["password"])
    assert step1.status_code == 200, step1.text
    assert otp_code, "OTP was not captured — _send_otp_email was not called"

    step2 = client.post(
        "/api/v1/auth/login/verify",
        json={"email": info["email"], "otp_code": otp_code},
    )
    assert step2.status_code == 200, step2.text
    return step2.json()["access_token"], info["user_id"]


# ── registration ──────────────────────────────────────────────────────────────

def test_register_success():
    r = client.post("/api/v1/auth/register", json={"email": _unique_email(), "password": "Abc123!"})
    assert r.status_code == 201
    data = r.json()
    assert "two_fa_secret" in data
    assert "user_id" in data


def test_register_duplicate_rejected():
    email = _unique_email()
    client.post("/api/v1/auth/register", json={"email": email, "password": "Abc123!"})
    r = client.post("/api/v1/auth/register", json={"email": email, "password": "Other!"})
    assert r.status_code == 400
    assert "already registered" in r.json()["detail"]


# ── login step 1: credential validation ──────────────────────────────────────

def test_login_wrong_password_rejected():
    info = _register()
    r, _ = _login_step1(info["email"], "WrongPassword!")
    assert r.status_code == 401


def test_login_unknown_email_rejected():
    r, _ = _login_step1("nobody@nowhere.example", "Pass123!")
    assert r.status_code == 401


def test_login_step1_sends_email_and_returns_code_sent():
    """Step 1 must call _send_otp_email and return status='code_sent'."""
    info = _register()
    step1, otp_code = _login_step1(info["email"], info["password"])

    assert step1.status_code == 200, step1.text
    body = step1.json()
    assert body["status"] == "code_sent"
    assert "@" in body["email"], "Masked email should still contain @"
    assert otp_code, "6-digit OTP must be captured from email call"
    assert otp_code.isdigit() and len(otp_code) == 6, f"OTP must be 6 digits, got: {otp_code!r}"


def test_login_step1_masks_email():
    """Returned email should be masked (e.g. 'al***@example.com'), not the full address."""
    info = _register(email="alice@example.com")
    step1, _ = _login_step1(info["email"], info["password"])
    assert step1.status_code == 200, step1.text
    returned_email = step1.json()["email"]
    assert returned_email != "alice@example.com", "Full email must not be returned"
    assert "@example.com" in returned_email, "Domain part should remain visible"


# ── login step 2: OTP verification → JWT ─────────────────────────────────────

def test_login_step2_correct_code_returns_jwt():
    """Correct 6-digit code must return a valid JWT that decodes to the right user."""
    info = _register()
    step1, otp_code = _login_step1(info["email"], info["password"])
    assert step1.status_code == 200

    step2 = client.post(
        "/api/v1/auth/login/verify",
        json={"email": info["email"], "otp_code": otp_code},
    )
    assert step2.status_code == 200, step2.text
    data = step2.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

    # JWT must decode to the correct user
    decoded = jwt.decode(data["access_token"], _JWT_SECRET, algorithms=[_JWT_ALGORITHM])
    assert int(decoded["sub"]) == info["user_id"]


def test_login_step2_wrong_code_rejected():
    """A wrong 6-digit code must return 401."""
    info = _register()
    step1, otp_code = _login_step1(info["email"], info["password"])
    assert step1.status_code == 200

    wrong_code = "000000" if otp_code != "000000" else "111111"
    step2 = client.post(
        "/api/v1/auth/login/verify",
        json={"email": info["email"], "otp_code": wrong_code},
    )
    assert step2.status_code == 401, step2.text


def test_login_step2_no_pending_code_rejected():
    """verify endpoint must reject a request when no OTP was ever sent."""
    info = _register()
    r = client.post(
        "/api/v1/auth/login/verify",
        json={"email": info["email"], "otp_code": "123456"},
    )
    assert r.status_code == 401


def test_login_step2_code_is_single_use():
    """After a successful verify the same OTP must be rejected on a second attempt."""
    info = _register()
    step1, otp_code = _login_step1(info["email"], info["password"])
    assert step1.status_code == 200

    # First use — succeeds
    first = client.post(
        "/api/v1/auth/login/verify",
        json={"email": info["email"], "otp_code": otp_code},
    )
    assert first.status_code == 200, first.text

    # Second use — must fail
    second = client.post(
        "/api/v1/auth/login/verify",
        json={"email": info["email"], "otp_code": otp_code},
    )
    assert second.status_code == 401, "Reused OTP must be rejected"


def test_login_step2_new_login_invalidates_old_code():
    """
    A second POST to /login must invalidate the first OTP.
    Trying the first code after a new login request must return 401.
    """
    info = _register()

    # First login request → capture first OTP
    _, otp_first = _login_step1(info["email"], info["password"])

    # Second login request → generates a new OTP, old one is deleted
    _, otp_second = _login_step1(info["email"], info["password"])

    # The first OTP is now stale — must be rejected
    r = client.post(
        "/api/v1/auth/login/verify",
        json={"email": info["email"], "otp_code": otp_first},
    )
    assert r.status_code == 401, "Stale OTP from a previous login request must be rejected"

    # The second OTP still works
    r2 = client.post(
        "/api/v1/auth/login/verify",
        json={"email": info["email"], "otp_code": otp_second},
    )
    assert r2.status_code == 200, r2.text


def test_login_step2_expired_code_rejected(monkeypatch):
    """
    An OTP that has passed its expiry timestamp must return 401 with a
    'Code expired' message.
    """
    from datetime import datetime, timedelta

    info = _register()
    step1, otp_code = _login_step1(info["email"], info["password"])
    assert step1.status_code == 200

    # Back-date *this user's* OTP expiry to the past so it appears expired.
    from sqlalchemy import select
    from models import LoginOTP, User
    import database

    async def _expire_otp():
        async with database.AsyncSessionLocal() as db:
            user_row = (await db.execute(
                select(User).where(User.email == info["email"])
            )).scalar_one_or_none()
            if user_row is None:
                return
            otp_row = (await db.execute(
                select(LoginOTP).where(LoginOTP.user_id == user_row.id)
            )).scalar_one_or_none()
            if otp_row:
                otp_row.expires_at = datetime.utcnow() - timedelta(minutes=1)
                await db.commit()

    import asyncio
    asyncio.run(_expire_otp())

    r = client.post(
        "/api/v1/auth/login/verify",
        json={"email": info["email"], "otp_code": otp_code},
    )
    assert r.status_code == 401, r.text
    assert "expired" in r.json()["detail"].lower()


# ── protected routes ──────────────────────────────────────────────────────────

def test_protected_route_no_token_rejected():
    r = client.post("/api/v1/onboarding/niche-dropdown", json={"chosen_niche": "Finance"})
    assert r.status_code in (401, 403)


def test_protected_route_forged_token_rejected():
    """Token signed with a different secret must be rejected."""
    forged = jwt.encode(
        {"sub": "1", "email": "x@x.com"},
        "wrong-secret-totally-different",
        algorithm=_JWT_ALGORITHM,
    )
    r = client.post(
        "/api/v1/onboarding/niche-dropdown",
        json={"chosen_niche": "Finance"},
        headers={"Authorization": f"Bearer {forged}"},
    )
    assert r.status_code == 401


def test_protected_route_valid_token_succeeds():
    token, user_id = register_and_login()
    r = client.post(
        "/api/v1/onboarding/niche-dropdown",
        json={"chosen_niche": "AI & Tech", "celebrity_tracker_string": "Elon Musk"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["user_id"] == user_id
    assert data["status"] == "success"


def test_user_id_comes_from_token_not_payload():
    """user_id in response must match token owner."""
    token, user_id = register_and_login()
    r = client.post(
        "/api/v1/onboarding/niche-dropdown",
        json={"chosen_niche": "Sports"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200
    assert r.json()["user_id"] == user_id


def test_series_setup_requires_auth():
    r = client.post(
        "/api/v1/onboarding/series-setup",
        json={
            "delivery_time": "09:00",
            "timezone": "UTC",
            "active_target_language": "en",
            "auto_create_podcast_series": False,
        },
    )
    assert r.status_code in (401, 403)


def test_login_success_returns_jwt():
    """End-to-end: register → login → verify → decoded JWT has correct user_id."""
    token, user_id = register_and_login()
    assert token
    payload = jwt.decode(token, _JWT_SECRET, algorithms=[_JWT_ALGORITHM])
    assert int(payload["sub"]) == user_id
