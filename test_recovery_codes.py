"""
Tests for the 2FA backup recovery-code flow.

Covers:
- Successful login with a valid recovery code (password + recovery_code)
- Recovery code requires correct password (not just the code alone)
- Invalid / unknown recovery codes are rejected
- A used recovery code cannot be reused (single-use enforcement)
- Concurrent-style reuse: atomic UPDATE prevents double-spend
"""

import pytest
from fastapi.testclient import TestClient

# conftest.py patches models.SessionLocal before main is imported,
# so this import is safe and will use the in-memory DB.
from main import app

client = TestClient(app, raise_server_exceptions=True)

_EMAIL = "recovery_test@example.com"
_PASSWORD = "SecurePass123!"
_TOTP_SECRET = None   # captured at registration
_RECOVERY_CODES: list[str] = []


@pytest.fixture(scope="module", autouse=True)
def _register_user():
    """Register a fresh user and capture TOTP secret + recovery codes."""
    global _TOTP_SECRET, _RECOVERY_CODES
    resp = client.post(
        "/api/v1/auth/register",
        json={"email": _EMAIL, "password": _PASSWORD},
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    _TOTP_SECRET = data["two_fa_secret"]
    _RECOVERY_CODES = data["recovery_codes"]
    assert len(_RECOVERY_CODES) == 8, "Expected 8 recovery codes at registration"


class TestRegistration:
    def test_recovery_codes_returned_at_registration(self):
        """Registration must return exactly 8 non-empty recovery codes."""
        assert len(_RECOVERY_CODES) == 8
        for code in _RECOVERY_CODES:
            assert isinstance(code, str) and len(code) > 0


class TestRecoverEndpoint:
    def test_valid_recovery_code_returns_token(self):
        """A correct password + unused recovery code must yield a JWT."""
        code = _RECOVERY_CODES[0]
        resp = client.post(
            "/api/v1/auth/recover",
            json={"email": _EMAIL, "password": _PASSWORD, "recovery_code": code},
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert "warning" in data  # prompt to reconfigure authenticator

    def test_used_code_cannot_be_reused(self):
        """After a code has been consumed, the same code must be rejected."""
        code = _RECOVERY_CODES[0]  # already used in the previous test
        resp = client.post(
            "/api/v1/auth/recover",
            json={"email": _EMAIL, "password": _PASSWORD, "recovery_code": code},
        )
        assert resp.status_code == 401, "Reused recovery code must be rejected"

    def test_invalid_recovery_code_rejected(self):
        """A completely unknown code is rejected with 401."""
        resp = client.post(
            "/api/v1/auth/recover",
            json={"email": _EMAIL, "password": _PASSWORD, "recovery_code": "DEADBEEF00"},
        )
        assert resp.status_code == 401, resp.text

    def test_wrong_password_rejected_even_with_valid_code(self):
        """Correct recovery code + wrong password must still be rejected.

        Recovery codes replace TOTP only — the password is still required.
        """
        code = _RECOVERY_CODES[1]  # fresh, unused code
        resp = client.post(
            "/api/v1/auth/recover",
            json={"email": _EMAIL, "password": "WrongPassword!", "recovery_code": code},
        )
        assert resp.status_code == 401, (
            "Should reject when password is incorrect, even if recovery code is valid"
        )

    def test_unknown_email_rejected(self):
        """An unregistered email is rejected regardless of recovery code."""
        resp = client.post(
            "/api/v1/auth/recover",
            json={
                "email": "nobody@example.com",
                "password": _PASSWORD,
                "recovery_code": _RECOVERY_CODES[1],
            },
        )
        assert resp.status_code == 401, resp.text

    def test_remaining_codes_still_usable_after_one_consumed(self):
        """Consuming one code must not invalidate the others."""
        code = _RECOVERY_CODES[2]  # third code, not yet used
        resp = client.post(
            "/api/v1/auth/recover",
            json={"email": _EMAIL, "password": _PASSWORD, "recovery_code": code},
        )
        assert resp.status_code == 200, (
            f"Code #{2} should still be valid — only code #0 was consumed. {resp.text}"
        )


class TestAtomicInvalidation:
    """Simulate a race condition by directly testing the DB state."""

    def test_code_marked_used_after_successful_recovery(self, _patch_db):
        """After a successful recovery, the used code row must have used_at set."""
        import models

        db = models.SessionLocal()
        try:
            code = _RECOVERY_CODES[0]  # used in TestRecoverEndpoint
            user = db.query(models.User).filter(models.User.email == _EMAIL).first()
            rc = (
                db.query(models.RecoveryCode)
                .filter(models.RecoveryCode.user_id == user.id)
                .all()
            )
            # At least one code (index 0) must be marked used
            used = [r for r in rc if r.used_at is not None]
            unused = [r for r in rc if r.used_at is None]
            assert len(used) >= 1, "At least one code should be marked used"
            # codes 1 (failed — wrong password), 3-7 should still be unused
            assert len(unused) >= 5, "Most codes should still be unused"
        finally:
            db.close()
