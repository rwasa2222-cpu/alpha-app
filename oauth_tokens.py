"""
OAuth token refresh helpers for ALPHA Automated Visual Podcast Factory.

Handles automatic refresh of expiring access tokens for:
  - YouTube (Google OAuth 2.0 refresh_token flow)
  - Instagram / Facebook / Threads (Meta Graph API long-lived token exchange)

Refresh credentials required (as Replit Secrets):
  GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET  — YouTube token refresh
  META_APP_ID / META_APP_SECRET            — Instagram, Facebook, and Threads refresh

Usage in distribution.py:
    from oauth_tokens import get_platform_token, ensure_token_fresh

    token_row = get_platform_token(user_id, "instagram", db)
    if token_row:
        ok, err = await ensure_token_fresh(token_row, db)
        if not ok:
            return {"status": "failed", "message": err}
        access_token = token_row.access_token   # may have been refreshed in-place
"""

import os
import httpx
from datetime import datetime, timedelta
from models import PlatformToken
from crypto import decrypt_token, encrypt_token

# Tokens expiring within this window are refreshed proactively before publishing
_REFRESH_THRESHOLD_SECONDS = 300   # 5 minutes


# ─────────────────────────────────────────────────────────────────────────────
# INTERNAL HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _is_near_expiry(token_row: PlatformToken) -> bool:
    """
    Returns True when the token should be refreshed before the next publish:

    1. token_expiry is set and falls within the refresh threshold (5 min) — the
       normal proactive-refresh path.
    2. token_expiry is None but a refresh_token is stored — we have no idea when
       the access token was issued or how long it lasts, so we attempt a refresh
       proactively rather than letting a stale token silently fail a publish.
       This covers tokens saved before expiry tracking was introduced.
    3. token_expiry is None and no refresh_token — nothing we can do; pass through
       and let the downstream API call surface any auth errors.
    """
    if token_row.token_expiry is None:
        # Attempt refresh when we have a refresh_token but no recorded expiry.
        return bool(token_row.refresh_token)
    threshold = datetime.utcnow() + timedelta(seconds=_REFRESH_THRESHOLD_SECONDS)
    return token_row.token_expiry <= threshold


async def _refresh_youtube_token(token_row: PlatformToken, db) -> tuple[bool, str]:
    """
    Refresh a YouTube access token via Google's token endpoint.

    Requires GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET Replit Secrets.
    On success updates token_row.access_token and token_row.token_expiry in-place
    and commits the change to the database.

    Returns (success: bool, error_message: str).
    """
    client_id     = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()

    if not token_row.refresh_token:
        return False, (
            "Your YouTube access token has expired and no refresh token is stored. "
            "Please reconnect your YouTube account to continue publishing."
        )
    if not client_id or not client_secret:
        return False, (
            "Your YouTube token is near expiry but GOOGLE_CLIENT_ID / "
            "GOOGLE_CLIENT_SECRET are not configured. Set these secrets to enable "
            "automatic token refresh, or reconnect your YouTube account."
        )

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "grant_type":    "refresh_token",
                    "refresh_token": decrypt_token(token_row.refresh_token),
                    "client_id":     client_id,
                    "client_secret": client_secret,
                },
            )
    except httpx.RequestError as exc:
        return False, f"Network error during YouTube token refresh: {exc}"

    if resp.status_code != 200:
        return False, (
            f"YouTube token refresh failed ({resp.status_code}): {resp.text[:300]}. "
            "Please reconnect your YouTube account."
        )

    data              = resp.json()
    new_access_token  = data.get("access_token")
    expires_in        = int(data.get("expires_in", 3600))   # Google default: 1 hour

    if not new_access_token:
        return False, (
            "YouTube token refresh response did not include an access_token. "
            "Please reconnect your YouTube account."
        )

    token_row.access_token = encrypt_token(new_access_token)
    token_row.token_expiry = datetime.utcnow() + timedelta(seconds=expires_in)
    db.commit()
    return True, ""


async def _refresh_meta_token(token_row: PlatformToken, db) -> tuple[bool, str]:
    """
    Exchange an Instagram / Facebook / Threads long-lived token for a fresh one
    via the Meta Graph API fb_exchange_token flow.

    Long-lived Meta tokens expire after ~60 days. Exchanging them resets the
    clock to another ~60 days without requiring user interaction.

    Requires META_APP_ID and META_APP_SECRET Replit Secrets.
    On success updates token_row.access_token and token_row.token_expiry in-place
    and commits the change to the database.

    Returns (success: bool, error_message: str).
    """
    app_id     = os.environ.get("META_APP_ID", "").strip()
    app_secret = os.environ.get("META_APP_SECRET", "").strip()
    label      = token_row.platform.capitalize()

    if not app_id or not app_secret:
        return False, (
            f"Your {label} token is near expiry but META_APP_ID / META_APP_SECRET "
            "are not configured. Set these secrets to enable automatic refresh, or "
            f"reconnect your {label} account."
        )

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                "https://graph.facebook.com/v19.0/oauth/access_token",
                params={
                    "grant_type":       "fb_exchange_token",
                    "client_id":        app_id,
                    "client_secret":    app_secret,
                    "fb_exchange_token": decrypt_token(token_row.access_token),
                },
            )
    except httpx.RequestError as exc:
        return False, f"Network error during {label} token refresh: {exc}"

    if resp.status_code != 200:
        return False, (
            f"{label} token refresh failed ({resp.status_code}): {resp.text[:300]}. "
            f"Please reconnect your {label} account."
        )

    data             = resp.json()
    new_access_token = data.get("access_token")
    # Meta returns expires_in in seconds; default is ~60 days (5 184 000 s)
    expires_in       = int(data.get("expires_in", 5_184_000))

    if not new_access_token:
        return False, (
            f"{label} token refresh response did not include an access_token. "
            f"Please reconnect your {label} account."
        )

    token_row.access_token = encrypt_token(new_access_token)
    token_row.token_expiry = datetime.utcnow() + timedelta(seconds=expires_in)
    db.commit()
    return True, ""


async def _refresh_linkedin_token(token_row: PlatformToken, db) -> tuple[bool, str]:
    """
    Refresh a LinkedIn OAuth access token using the stored refresh_token.

    LinkedIn member tokens last up to 60 days; refresh tokens last up to 1 year.
    Requires LINKEDIN_CLIENT_ID and LINKEDIN_CLIENT_SECRET Replit Secrets.

    Returns (success: bool, error_message: str).
    """
    client_id     = os.environ.get("LINKEDIN_CLIENT_ID", "").strip()
    client_secret = os.environ.get("LINKEDIN_CLIENT_SECRET", "").strip()

    if not token_row.refresh_token:
        return False, (
            "Your LinkedIn access token has expired and no refresh token is stored. "
            "Please reconnect your LinkedIn account to continue publishing."
        )
    if not client_id or not client_secret:
        return False, (
            "Your LinkedIn token is near expiry but LINKEDIN_CLIENT_ID / "
            "LINKEDIN_CLIENT_SECRET are not configured. Set these secrets to enable "
            "automatic token refresh, or reconnect your LinkedIn account."
        )

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                "https://www.linkedin.com/oauth/v2/accessToken",
                data={
                    "grant_type":    "refresh_token",
                    "refresh_token": decrypt_token(token_row.refresh_token),
                    "client_id":     client_id,
                    "client_secret": client_secret,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
    except httpx.RequestError as exc:
        return False, f"Network error during LinkedIn token refresh: {exc}"

    if resp.status_code != 200:
        return False, (
            f"LinkedIn token refresh failed ({resp.status_code}): {resp.text[:300]}. "
            "Please reconnect your LinkedIn account."
        )

    data             = resp.json()
    new_access_token = data.get("access_token")
    expires_in       = int(data.get("expires_in", 5_184_000))   # default 60 days

    if not new_access_token:
        return False, (
            "LinkedIn token refresh response did not include an access_token. "
            "Please reconnect your LinkedIn account."
        )

    token_row.access_token = encrypt_token(new_access_token)
    token_row.token_expiry = datetime.utcnow() + timedelta(seconds=expires_in)
    # LinkedIn may rotate the refresh token
    new_refresh_token = data.get("refresh_token")
    if new_refresh_token:
        token_row.refresh_token = encrypt_token(new_refresh_token)
    db.commit()
    return True, ""


async def _refresh_tiktok_token(token_row: PlatformToken, db) -> tuple[bool, str]:
    """
    Refresh a TikTok OAuth access token using the stored refresh_token.

    TikTok access tokens expire after 24 hours; refresh tokens last 365 days.
    Requires TIKTOK_CLIENT_KEY and TIKTOK_CLIENT_SECRET Replit Secrets.

    Returns (success: bool, error_message: str).
    """
    client_key    = os.environ.get("TIKTOK_CLIENT_KEY", "").strip()
    client_secret = os.environ.get("TIKTOK_CLIENT_SECRET", "").strip()

    if not token_row.refresh_token:
        return False, (
            "Your TikTok access token has expired and no refresh token is stored. "
            "Please reconnect your TikTok account to continue publishing."
        )
    if not client_key or not client_secret:
        return False, (
            "Your TikTok token is near expiry but TIKTOK_CLIENT_KEY / "
            "TIKTOK_CLIENT_SECRET are not configured. Set these secrets to enable "
            "automatic token refresh, or reconnect your TikTok account."
        )

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                "https://open.tiktokapis.com/v2/oauth/token/",
                data={
                    "client_key":    client_key,
                    "client_secret": client_secret,
                    "grant_type":    "refresh_token",
                    "refresh_token": decrypt_token(token_row.refresh_token),
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
    except httpx.RequestError as exc:
        return False, f"Network error during TikTok token refresh: {exc}"

    if resp.status_code != 200:
        return False, (
            f"TikTok token refresh failed ({resp.status_code}): {resp.text[:300]}. "
            "Please reconnect your TikTok account."
        )

    data             = resp.json()
    new_access_token = data.get("access_token")
    expires_in       = int(data.get("expires_in", 86_400))   # default 24 hours

    if not new_access_token:
        return False, (
            "TikTok token refresh response did not include an access_token. "
            "Please reconnect your TikTok account."
        )

    token_row.access_token = encrypt_token(new_access_token)
    token_row.token_expiry = datetime.utcnow() + timedelta(seconds=expires_in)
    # TikTok always rotates the refresh token on each use
    new_refresh_token = data.get("refresh_token")
    if new_refresh_token:
        token_row.refresh_token = encrypt_token(new_refresh_token)
    db.commit()
    return True, ""


# Maps platform name → refresh function
_REFRESH_HANDLERS: dict = {
    "youtube":   _refresh_youtube_token,
    "instagram": _refresh_meta_token,
    "facebook":  _refresh_meta_token,
    "threads":   _refresh_meta_token,
    "linkedin":  _refresh_linkedin_token,
    "tiktok":    _refresh_tiktok_token,
}


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC API
# ─────────────────────────────────────────────────────────────────────────────

async def ensure_token_fresh(token_row: PlatformToken, db) -> tuple[bool, str]:
    """
    Check whether a stored platform token is near expiry and proactively refresh it.

    Returns:
        (True, "")         — token is valid (and may have been refreshed in-place).
        (False, "<msg>")   — refresh failed; message is user-facing and actionable,
                             e.g. "token expired — please reconnect".
    """
    if not _is_near_expiry(token_row):
        return True, ""

    handler = _REFRESH_HANDLERS.get(token_row.platform)
    if handler is None:
        # Platform has no automatic refresh path. If the expiry is known and
        # has already passed, surface a deterministic "reconnect required" error
        # rather than letting the downstream API call fail with a cryptic auth
        # error. If expiry is unknown (None) we pass through.
        if token_row.token_expiry is not None and token_row.token_expiry <= datetime.utcnow():
            label = token_row.platform.capitalize()
            return False, (
                f"Your {label} access token has expired. "
                f"Please reconnect your {label} account to continue publishing."
            )
        return True, ""

    return await handler(token_row, db)


def get_platform_token(user_id: int, platform: str, db) -> PlatformToken | None:
    """
    Retrieve the stored PlatformToken row for a user + platform combination.
    Returns None if the user has not connected that platform.
    """
    return (
        db.query(PlatformToken)
        .filter(
            PlatformToken.user_id == user_id,
            PlatformToken.platform == platform,
        )
        .first()
    )
