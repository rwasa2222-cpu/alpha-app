"""
Integration tests for POST /api/v1/script/generate.

All tests use an in-memory SQLite database and mock the Nemotron call so no
real NVIDIA API credit is consumed.

get_current_user is overridden via app.dependency_overrides so tests bypass
TOTP and the revoked-token blacklist — login machinery is not the SUT here.
"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select as sa_select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

os.environ.setdefault("SESSION_SECRET", "test-secret-at-least-32-chars-long!!")
os.environ.setdefault("NVIDIA_API_KEY", "test-nvidia-key")

# ── In-memory async engine — shared for the whole session ────────────────────

_ASYNC_ENGINE = create_async_engine(
    "sqlite+aiosqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
_SESSION_FACTORY: async_sessionmaker | None = None


@pytest_asyncio.fixture(scope="session", autouse=True)
async def _setup_async_db():
    """Create all tables once, share the engine for the entire session."""
    global _SESSION_FACTORY
    from models import Base
    async with _ASYNC_ENGINE.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    _SESSION_FACTORY = async_sessionmaker(
        bind=_ASYNC_ENGINE, expire_on_commit=False, class_=AsyncSession
    )
    yield
    await _ASYNC_ENGINE.dispose()


# ── Helper: build an authenticated client (get_current_user overridden) ───────

def _make_fake_user():
    # SimpleNamespace avoids SQLAlchemy instrumentation setup that
    # User.__new__(User) would require.  The endpoint never reads user
    # attributes beyond confirming the user exists.
    from types import SimpleNamespace
    return SimpleNamespace(id=999, email="testscript@example.com", username="tester")


@asynccontextmanager
async def _auth_client():
    """
    Async HTTP client pointed at the FastAPI app.
    - get_async_db  → in-memory SQLite
    - get_current_user → synthetic User (no TOTP / token check)
    """
    from database import get_async_db
    from main import app, get_current_user

    async def _db():
        async with _SESSION_FACTORY() as session:
            yield session

    async def _user():
        return _make_fake_user()

    app.dependency_overrides[get_async_db] = _db
    app.dependency_overrides[get_current_user] = _user
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            yield c
    finally:
        app.dependency_overrides.pop(get_current_user, None)
        app.dependency_overrides.pop(get_async_db, None)


@asynccontextmanager
async def _no_auth_client():
    """
    Async HTTP client with only the DB overridden — get_current_user is the
    real implementation, so requests without a valid Bearer token are rejected.
    """
    from database import get_async_db
    from main import app

    async def _db():
        async with _SESSION_FACTORY() as session:
            yield session

    app.dependency_overrides[get_async_db] = _db
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            yield c
    finally:
        app.dependency_overrides.pop(get_async_db, None)


# ── Constants ─────────────────────────────────────────────────────────────────

_ENDPOINT = "/api/v1/script/generate"
# A plausible-looking header — not validated because get_current_user is overridden.
_AUTH = {"Authorization": "Bearer test.jwt.token"}

_GOOD_SCRIPT = {
    "body": "AI-generated analytical script about Finance featuring Elon Musk.",
    "titleHook": "📊 Elon's Next Market Move Revealed",
    "imagePrompt": "Cinematic financial analysis, dark moody, glowing blue charts, 8K",
    "subtitles": [
        "Market signal detected",
        "Elon Musk in focus",
        "Data confirms trend",
        "Analysts alarmed",
        "Act now",
    ],
}


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestScriptGenerate:

    @pytest.mark.asyncio
    async def test_unauthenticated_returns_401(self):
        """No JWT → 401/403 Unauthorized (real get_current_user runs)."""
        async with _no_auth_client() as client:
            resp = await client.post(
                _ENDPOINT,
                json={"niche": "Finance", "celebrities": [], "perspective": "analytical"},
                # Deliberately no Authorization header
            )
        # HTTPBearer returns 403 when header is absent; get_current_user
        # returns 401 when token is invalid — either confirms auth is enforced.
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_invalid_perspective_returns_422(self):
        """Unknown perspective value is rejected before the AI call."""
        async with _auth_client() as client:
            resp = await client.post(
                _ENDPOINT,
                headers=_AUTH,
                json={"niche": "Finance", "celebrities": [], "perspective": "snarky_pirate"},
            )
        assert resp.status_code == 422
        assert "perspective" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_successful_generation_returns_all_fields(self):
        """Happy path: mocked Nemotron → all required keys present in response."""
        async with _auth_client() as client:
            with patch(
                "tasks.generate_script_for_perspective",
                new=AsyncMock(return_value=_GOOD_SCRIPT),
            ):
                resp = await client.post(
                    _ENDPOINT,
                    headers=_AUTH,
                    json={
                        "niche": "Finance",
                        "celebrities": ["Elon Musk"],
                        "perspective": "analytical",
                    },
                )
        assert resp.status_code == 200
        data = resp.json()
        assert data["body"] == _GOOD_SCRIPT["body"]
        assert data["titleHook"] == _GOOD_SCRIPT["titleHook"]
        assert data["imagePrompt"] == _GOOD_SCRIPT["imagePrompt"]
        assert data["subtitles"] == _GOOD_SCRIPT["subtitles"]
        assert data["perspective"] == "analytical"

    @pytest.mark.asyncio
    async def test_all_valid_perspectives_accepted(self):
        """Each of the four perspective IDs is accepted without 422."""
        async with _auth_client() as client:
            for perspective in ("analytical", "hype", "humorous", "reporter"):
                with patch(
                    "tasks.generate_script_for_perspective",
                    new=AsyncMock(return_value=_GOOD_SCRIPT),
                ):
                    resp = await client.post(
                        _ENDPOINT,
                        headers=_AUTH,
                        json={"niche": "Tech", "celebrities": [], "perspective": perspective},
                    )
                assert resp.status_code == 200, (
                    f"Failed for perspective={perspective}: {resp.text}"
                )
                assert resp.json()["perspective"] == perspective

    @pytest.mark.asyncio
    async def test_nemotron_runtime_error_returns_502(self):
        """When Nemotron raises RuntimeError → 502 Bad Gateway."""
        async with _auth_client() as client:
            with patch(
                "tasks.generate_script_for_perspective",
                new=AsyncMock(side_effect=RuntimeError("NVIDIA API error 500: internal")),
            ):
                resp = await client.post(
                    _ENDPOINT,
                    headers=_AUTH,
                    json={"niche": "Finance", "celebrities": [], "perspective": "hype"},
                )
        assert resp.status_code == 502
        assert "NVIDIA" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_missing_api_key_returns_503(self):
        """EnvironmentError (missing API key) → 503 Service Unavailable."""
        async with _auth_client() as client:
            with patch(
                "tasks.generate_script_for_perspective",
                new=AsyncMock(
                    side_effect=EnvironmentError("NVIDIA_API_KEY secret is not set.")
                ),
            ):
                resp = await client.post(
                    _ENDPOINT,
                    headers=_AUTH,
                    json={"niche": "Finance", "celebrities": [], "perspective": "reporter"},
                )
        assert resp.status_code == 503
        assert "NVIDIA_API_KEY" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_malformed_nemotron_response_returns_502(self):
        """ValueError (non-JSON model output) → 502."""
        async with _auth_client() as client:
            with patch(
                "tasks.generate_script_for_perspective",
                new=AsyncMock(
                    side_effect=ValueError("Nemotron returned unexpected format: ...")
                ),
            ):
                resp = await client.post(
                    _ENDPOINT,
                    headers=_AUTH,
                    json={"niche": "Finance", "celebrities": [], "perspective": "humorous"},
                )
        assert resp.status_code == 502
        assert "Nemotron" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_empty_celebrities_list_accepted(self):
        """Empty celebrities list is valid — prompt falls back to 'notable public figures'."""
        async with _auth_client() as client:
            with patch(
                "tasks.generate_script_for_perspective",
                new=AsyncMock(return_value=_GOOD_SCRIPT),
            ):
                resp = await client.post(
                    _ENDPOINT,
                    headers=_AUTH,
                    json={"niche": "Health", "celebrities": [], "perspective": "reporter"},
                )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_single_celebrity_accepted(self):
        """A single celebrity in the list is accepted and forwarded to the AI call."""
        captured_calls: list = []

        async def _mock_generate(niche, celebrities, perspective):
            captured_calls.append({"niche": niche, "celebrities": celebrities})
            return _GOOD_SCRIPT

        async with _auth_client() as client:
            with patch("tasks.generate_script_for_perspective", new=_mock_generate):
                resp = await client.post(
                    _ENDPOINT,
                    headers=_AUTH,
                    json={
                        "niche": "Sports",
                        "celebrities": ["Cristiano Ronaldo"],
                        "perspective": "hype",
                    },
                )
        assert resp.status_code == 200
        # Confirm the single celebrity was passed through
        assert len(captured_calls) == 1
        assert "Cristiano Ronaldo" in captured_calls[0]["celebrities"]

    @pytest.mark.asyncio
    async def test_blank_niche_falls_back_to_default(self):
        """A blank niche string falls back to the schema default ('Finance') not an empty string."""
        captured_calls: list = []

        async def _mock_generate(niche, celebrities, perspective):
            captured_calls.append({"niche": niche})
            return _GOOD_SCRIPT

        async with _auth_client() as client:
            with patch("tasks.generate_script_for_perspective", new=_mock_generate):
                # Send an explicitly blank niche — the endpoint should not forward ""
                resp = await client.post(
                    _ENDPOINT,
                    headers=_AUTH,
                    json={"niche": "", "celebrities": [], "perspective": "analytical"},
                )
        assert resp.status_code == 200
        # A blank niche is falsy; the endpoint resolves to the schema default ("Finance")
        # or any non-empty DB niche — never an empty string.
        assert len(captured_calls) == 1
        assert captured_calls[0]["niche"]  # must be truthy (non-blank)

    @pytest.mark.asyncio
    async def test_very_short_niche_accepted(self):
        """A very short but non-blank niche string ('AI') is accepted and forwarded."""
        captured_calls: list = []

        async def _mock_generate(niche, celebrities, perspective):
            captured_calls.append({"niche": niche})
            return _GOOD_SCRIPT

        async with _auth_client() as client:
            with patch("tasks.generate_script_for_perspective", new=_mock_generate):
                resp = await client.post(
                    _ENDPOINT,
                    headers=_AUTH,
                    json={"niche": "AI", "celebrities": [], "perspective": "analytical"},
                )
        assert resp.status_code == 200
        assert len(captured_calls) == 1
        assert captured_calls[0]["niche"] == "AI"

    @pytest.mark.asyncio
    async def test_fresh_user_no_db_rows_uses_default_niche(self):
        """
        A brand-new user with zero UserAestheticSetting and UserSelectedSource rows
        must not cause a KeyError or NoneType crash.

        The payload omits niche and celebrities entirely so schema defaults
        ('Finance' and []) are the only source of those values — confirming
        that the endpoint works end-to-end when neither the request body nor
        the DB supplies any configuration.

        Uses a distinct synthetic user ID (user_id=8888) that is explicitly
        verified to have no rows in either enrichment table before the request.
        """
        # ── Isolated synthetic user with no DB rows ───────────────────────────
        _FRESH_USER_ID = 8888

        from types import SimpleNamespace
        fresh_user = SimpleNamespace(
            id=_FRESH_USER_ID,
            email="freshuser@example.com",
            username="freshuser",
        )

        from database import get_async_db
        from main import app, get_current_user
        from models import UserAestheticSetting, UserSelectedSource

        async def _fresh_db():
            async with _SESSION_FACTORY() as session:
                yield session

        async def _fresh_user():
            return fresh_user

        app.dependency_overrides[get_async_db] = _fresh_db
        app.dependency_overrides[get_current_user] = _fresh_user

        try:
            # ── Assert zero DB rows for this user before the request ──────────
            async with _SESSION_FACTORY() as session:
                settings_rows = (await session.execute(
                    sa_select(UserAestheticSetting).where(
                        UserAestheticSetting.user_id == _FRESH_USER_ID
                    )
                )).scalars().all()
                source_rows = (await session.execute(
                    sa_select(UserSelectedSource).where(
                        UserSelectedSource.user_id == _FRESH_USER_ID
                    )
                )).scalars().all()
            assert settings_rows == [], (
                f"Precondition failed: user {_FRESH_USER_ID} already has UserAestheticSetting rows"
            )
            assert source_rows == [], (
                f"Precondition failed: user {_FRESH_USER_ID} already has UserSelectedSource rows"
            )

            # ── Send the request with only perspective — niche and celebrities
            # are intentionally omitted so ScriptGenerateSchema applies its
            # defaults (niche="Finance", celebrities=[]).
            captured_calls: list = []

            async def _mock_generate(niche, celebrities, perspective):
                captured_calls.append({"niche": niche, "celebrities": celebrities})
                return _GOOD_SCRIPT

            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                with patch("tasks.generate_script_for_perspective", new=_mock_generate):
                    resp = await client.post(
                        _ENDPOINT,
                        headers=_AUTH,
                        json={"perspective": "analytical"},  # niche + celebrities omitted
                    )

        finally:
            app.dependency_overrides.pop(get_current_user, None)
            app.dependency_overrides.pop(get_async_db, None)

        assert resp.status_code == 200, (
            f"Expected 200 for fresh user with no DB rows; got {resp.status_code}: {resp.text}"
        )
        assert len(captured_calls) == 1, "generate_script_for_perspective was not called"

        # Niche forwarded to the AI must be the schema default — never empty or None
        forwarded_niche = captured_calls[0]["niche"]
        assert forwarded_niche, (
            "Niche forwarded to AI is falsy — DB enrichment crashed or returned None"
        )
        assert forwarded_niche == "Finance", (
            f"Expected schema default niche 'Finance' for a fresh user; got '{forwarded_niche}'"
        )

        # Celebrity list should be empty (no DB rows, omitted from payload)
        assert captured_calls[0]["celebrities"] == [], (
            f"Expected empty celebrities list for a fresh user; got {captured_calls[0]['celebrities']}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Unit tests for generate_script_for_perspective() directly
# These bypass the HTTP layer to test JSON-parse fallback logic.
# ─────────────────────────────────────────────────────────────────────────────

class TestGenerateScriptForPerspectiveUnit:
    """Direct unit tests for tasks.generate_script_for_perspective()."""

    def _make_nvidia_response(self, content: str, status_code: int = 200):
        """Build a fake httpx Response-like object for AsyncMock."""
        import httpx

        return httpx.Response(
            status_code=status_code,
            json={
                "choices": [{"message": {"content": content}}]
            },
        )

    @pytest.mark.asyncio
    async def test_valid_json_response_returns_structured_dict(self):
        """Well-formed JSON from Nemotron → structured dict with all four keys."""
        import json
        from tasks import generate_script_for_perspective

        valid_payload = json.dumps({
            "body": "Full script text here.",
            "titleHook": "🔥 Test Title",
            "imagePrompt": "Cinematic dark city skyline",
            "subtitles": ["Line one", "Line two", "Line three", "Line four", "Line five"],
        })
        fake_response = self._make_nvidia_response(valid_payload)

        with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=fake_response)):
            result = await generate_script_for_perspective(
                niche="Finance",
                celebrities=["Elon Musk"],
                perspective="analytical",
            )

        assert result["body"] == "Full script text here."
        assert result["titleHook"] == "🔥 Test Title"
        assert result["imagePrompt"] == "Cinematic dark city skyline"
        assert len(result["subtitles"]) == 5

    @pytest.mark.asyncio
    async def test_non_json_model_response_raises_value_error(self):
        """Non-JSON content from Nemotron raises ValueError (tested JSON-parse fallback path)."""
        from tasks import generate_script_for_perspective

        fake_response = self._make_nvidia_response(
            "Sorry, I cannot generate that content."
        )

        with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=fake_response)):
            with pytest.raises(ValueError, match="unexpected format"):
                await generate_script_for_perspective(
                    niche="Finance",
                    celebrities=[],
                    perspective="reporter",
                )

    @pytest.mark.asyncio
    async def test_markdown_fenced_json_is_parsed_correctly(self):
        """JSON wrapped in ```json ... ``` fences is correctly unwrapped and parsed."""
        import json
        from tasks import generate_script_for_perspective

        inner = json.dumps({
            "body": "Fenced script body.",
            "titleHook": "Fenced Hook",
            "imagePrompt": "Vivid image prompt",
            "subtitles": ["A", "B", "C", "D", "E"],
        })
        fenced_content = f"```json\n{inner}\n```"
        fake_response = self._make_nvidia_response(fenced_content)

        with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=fake_response)):
            result = await generate_script_for_perspective(
                niche="Tech",
                celebrities=["Sam Altman"],
                perspective="hype",
            )

        assert result["body"] == "Fenced script body."
        assert result["titleHook"] == "Fenced Hook"

    @pytest.mark.asyncio
    async def test_empty_celebrities_uses_fallback_label(self):
        """Empty celebrities list → 'notable public figures' label in the prompt (no crash)."""
        import json
        from tasks import generate_script_for_perspective

        valid_payload = json.dumps({
            "body": "Script with no celebrities.",
            "titleHook": "No Stars Hook",
            "imagePrompt": "Generic studio backdrop",
            "subtitles": ["One", "Two", "Three", "Four", "Five"],
        })
        fake_response = self._make_nvidia_response(valid_payload)

        with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=fake_response)):
            result = await generate_script_for_perspective(
                niche="Health",
                celebrities=[],
                perspective="humorous",
            )

        assert result["body"] == "Script with no celebrities."
        assert isinstance(result["subtitles"], list)
        assert len(result["subtitles"]) == 5

    @pytest.mark.asyncio
    async def test_missing_subtitles_in_response_uses_fallback(self):
        """When model JSON omits 'subtitles', the function fills in a 5-item fallback list."""
        import json
        from tasks import generate_script_for_perspective

        # Response without subtitles key
        partial_payload = json.dumps({
            "body": "Script with no subtitles field.",
            "titleHook": "No Subtitles Hook",
            "imagePrompt": "Dark city",
        })
        fake_response = self._make_nvidia_response(partial_payload)

        with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=fake_response)):
            result = await generate_script_for_perspective(
                niche="Crypto",
                celebrities=["Vitalik Buterin"],
                perspective="analytical",
            )

        assert isinstance(result["subtitles"], list)
        assert len(result["subtitles"]) == 5

    @pytest.mark.asyncio
    async def test_zero_subtitles_in_response_padded_to_five(self):
        """Nemotron returns an empty subtitles list → padded to exactly 5 strings."""
        import json
        from tasks import generate_script_for_perspective

        payload = json.dumps({
            "body": "Script body.",
            "titleHook": "Hook",
            "imagePrompt": "Prompt",
            "subtitles": [],
        })
        fake_response = self._make_nvidia_response(payload)

        with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=fake_response)):
            result = await generate_script_for_perspective(
                niche="Finance",
                celebrities=["Elon Musk"],
                perspective="analytical",
            )

        assert isinstance(result["subtitles"], list)
        assert len(result["subtitles"]) == 5
        assert all(isinstance(s, str) and s for s in result["subtitles"])

    @pytest.mark.asyncio
    async def test_one_subtitle_in_response_padded_to_five(self):
        """Nemotron returns 1 subtitle → remaining 4 slots filled with fallback strings."""
        import json
        from tasks import generate_script_for_perspective

        payload = json.dumps({
            "body": "Script body.",
            "titleHook": "Hook",
            "imagePrompt": "Prompt",
            "subtitles": ["Only one subtitle"],
        })
        fake_response = self._make_nvidia_response(payload)

        with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=fake_response)):
            result = await generate_script_for_perspective(
                niche="Tech",
                celebrities=[],
                perspective="hype",
            )

        assert isinstance(result["subtitles"], list)
        assert len(result["subtitles"]) == 5
        # The provided subtitle must be preserved as the first entry
        assert result["subtitles"][0] == "Only one subtitle"
        assert all(isinstance(s, str) and s for s in result["subtitles"])

    @pytest.mark.asyncio
    async def test_three_subtitles_in_response_padded_to_five(self):
        """Nemotron returns 3 subtitles → remaining 2 slots filled with fallback strings."""
        import json
        from tasks import generate_script_for_perspective

        provided = ["First", "Second", "Third"]
        payload = json.dumps({
            "body": "Script body.",
            "titleHook": "Hook",
            "imagePrompt": "Prompt",
            "subtitles": provided,
        })
        fake_response = self._make_nvidia_response(payload)

        with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=fake_response)):
            result = await generate_script_for_perspective(
                niche="Sports",
                celebrities=["Cristiano Ronaldo"],
                perspective="reporter",
            )

        assert isinstance(result["subtitles"], list)
        assert len(result["subtitles"]) == 5
        # All three provided subtitles must be preserved in order
        assert result["subtitles"][:3] == provided
        assert all(isinstance(s, str) and s for s in result["subtitles"])

    @pytest.mark.asyncio
    async def test_nvidia_api_non_200_raises_runtime_error(self):
        """Non-200 status from NVIDIA API raises RuntimeError (mapped to 502 by the endpoint)."""
        import httpx
        from tasks import generate_script_for_perspective

        error_response = httpx.Response(
            status_code=500,
            text="Internal Server Error",
        )

        with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=error_response)):
            with pytest.raises(RuntimeError, match="NVIDIA Nemotron API error 500"):
                await generate_script_for_perspective(
                    niche="Sports",
                    celebrities=["LeBron James"],
                    perspective="reporter",
                )


# ─────────────────────────────────────────────────────────────────────────────
# Ideogram image-generation fallback tests (endpoint layer)
# ─────────────────────────────────────────────────────────────────────────────

class TestIdeogramFallback:
    """
    Confirm that the /api/v1/script/generate endpoint handles Ideogram failures
    gracefully: the script is still returned with HTTP 200 and graphic_card_url
    is null when image generation is unavailable.
    """

    @pytest.mark.asyncio
    async def test_ideogram_exception_returns_200_with_null_graphic_card_url(self):
        """
        When Ideogram raises any exception, the endpoint must still return 200
        with the full script payload and graphic_card_url set to null.
        The image failure must not propagate to the caller.
        """
        async with _auth_client() as client:
            with patch(
                "tasks.generate_script_for_perspective",
                new=AsyncMock(return_value=_GOOD_SCRIPT),
            ):
                with patch(
                    "tasks.generate_ideogram_background",
                    new=AsyncMock(side_effect=RuntimeError("Ideogram API error 503: service unavailable")),
                ):
                    resp = await client.post(
                        _ENDPOINT,
                        headers=_AUTH,
                        json={
                            "niche": "Finance",
                            "celebrities": ["Elon Musk"],
                            "perspective": "analytical",
                        },
                    )

        assert resp.status_code == 200
        data = resp.json()
        # Script fields are intact
        assert data["body"] == _GOOD_SCRIPT["body"]
        assert data["titleHook"] == _GOOD_SCRIPT["titleHook"]
        assert data["perspective"] == "analytical"
        # Image URL must be null — not a broken path or missing key
        assert "graphic_card_url" in data
        assert data["graphic_card_url"] is None

    @pytest.mark.asyncio
    async def test_ideogram_success_returns_valid_storage_path(self):
        """
        When Ideogram succeeds, graphic_card_url must be a non-empty string
        that starts with /assets/storage/ so the frontend preview box can
        load it as a relative URL.
        """
        fake_image_path = "/assets/storage/script_preview_999_abc12345.png"

        async with _auth_client() as client:
            with patch(
                "tasks.generate_script_for_perspective",
                new=AsyncMock(return_value=_GOOD_SCRIPT),
            ):
                with patch(
                    "tasks.generate_ideogram_background",
                    new=AsyncMock(return_value=fake_image_path),
                ):
                    resp = await client.post(
                        _ENDPOINT,
                        headers=_AUTH,
                        json={
                            "niche": "Finance",
                            "celebrities": ["Elon Musk"],
                            "perspective": "analytical",
                        },
                    )

        assert resp.status_code == 200
        data = resp.json()
        assert data["graphic_card_url"] is not None
        assert data["graphic_card_url"].startswith("/assets/storage/")
        assert data["graphic_card_url"].endswith(".png")
