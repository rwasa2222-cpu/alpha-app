"""
Tests for Voicebox voice synthesis path guards — Task 17.

Covers:
- voice-studio endpoint returns HTTP 503 with an actionable message when the
  Voicebox provider returns 404 on POST /clone
- startup_event logs a warning (not an exception) when the Voicebox /health
  endpoint is unreachable (ConnectError)

conftest.py patches models.SessionLocal to use an in-memory SQLite DB so
these tests never touch alpha.db and run reproducibly from a clean state.
"""

import io
import os
import uuid
import asyncio
import logging
import pyotp
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


# ── helpers ───────────────────────────────────────────────────────────────────

def _unique_email() -> str:
    return f"vb_test_{uuid.uuid4().hex[:8]}@test.com"


def _register_and_login(email: str | None = None, password: str = "Pass123!"):
    email = email or _unique_email()
    reg = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": password},
    )
    assert reg.status_code == 201, reg.text
    totp_secret = reg.json()["two_fa_secret"]
    code = pyotp.TOTP(totp_secret).now()
    login = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password, "totp_code": code},
    )
    assert login.status_code == 200, login.text
    return login.json()["access_token"]


# ── Test 1: voice-studio returns 503 when Voicebox /clone returns 404 ─────────

def test_voice_studio_clone_404_returns_503_with_actionable_message():
    """
    When the Voicebox provider responds 404 to POST /clone, the voice-studio
    endpoint must return HTTP 503 with a message that names the misconfigured
    path so the operator knows exactly what to fix.
    """
    token = _register_and_login()

    # Build a fake 404 response from the Voicebox /clone endpoint
    mock_404_response = MagicMock()
    mock_404_response.status_code = 404
    mock_404_response.text = "Not Found"

    mock_async_client = AsyncMock()
    mock_async_client.__aenter__ = AsyncMock(return_value=mock_async_client)
    mock_async_client.__aexit__ = AsyncMock(return_value=False)
    mock_async_client.post = AsyncMock(return_value=mock_404_response)

    fake_audio = io.BytesIO(b"\xff\xfb\x90\x00" * 16)  # minimal fake MP3 bytes

    with patch.dict(
        os.environ,
        {"VOICEBOX_API_ENDPOINT": "https://fake-voicebox.example.com", "VOICEBOX_API_KEY": "test-key"},
    ):
        with patch("httpx.AsyncClient", return_value=mock_async_client):
            response = client.post(
                "/api/v1/onboarding/voice-studio?voice_selection=clone",
                files={"sample_file": ("voice_sample.mp3", fake_audio, "audio/mpeg")},
                headers={"Authorization": f"Bearer {token}"},
            )

    assert response.status_code == 503, (
        f"Expected 503 when Voicebox /clone returns 404, got {response.status_code}: {response.text}"
    )
    detail = response.json().get("detail", "")
    # The message must tell the operator which path is wrong
    assert "404" in detail, f"Status code not mentioned in error detail: {detail!r}"
    assert "/clone" in detail, f"Misconfigured path not mentioned in error detail: {detail!r}"


# ── Test 2: startup health check logs warning when /health is unreachable ─────

def test_startup_health_check_logs_warning_on_connect_error(caplog):
    """
    When httpx raises ConnectError reaching VOICEBOX_API_ENDPOINT/health,
    startup_event must log a WARNING (not raise an exception) so the server
    still starts and the operator is informed of the misconfiguration.
    """
    import httpx
    from main import startup_event

    with patch.dict(
        os.environ,
        {"VOICEBOX_API_ENDPOINT": "https://unreachable-voicebox.example.com", "VOICEBOX_API_KEY": "test-key"},
    ):
        mock_async_client = AsyncMock()
        mock_async_client.__aenter__ = AsyncMock(return_value=mock_async_client)
        mock_async_client.__aexit__ = AsyncMock(return_value=False)
        mock_async_client.get = AsyncMock(
            side_effect=httpx.ConnectError("Connection refused")
        )

        with patch("httpx.AsyncClient", return_value=mock_async_client):
            with caplog.at_level(logging.WARNING):
                asyncio.run(startup_event())

    warning_messages = [r.message for r in caplog.records if r.levelno == logging.WARNING]
    voicebox_warnings = [m for m in warning_messages if "Voicebox" in m or "voicebox" in m.lower()]

    assert voicebox_warnings, (
        "Expected at least one WARNING log mentioning Voicebox when /health is unreachable. "
        f"All captured warnings: {warning_messages}"
    )
    # The warning must be actionable — it should mention the URL or the problem
    combined = " ".join(voicebox_warnings)
    assert any(
        phrase in combined
        for phrase in ("unreachable", "could not reach", "Check", "VOICEBOX_API_ENDPOINT")
    ), f"Warning is not actionable: {combined!r}"
