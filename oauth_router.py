"""OAuth2 platform connect & callback router.

Implements:
  GET /api/v1/auth/connect/{platform}   — build the platform's authorization URL
  GET /api/v1/auth/callback/{platform}  — exchange the code, encrypt & persist tokens

Supported platforms: youtube, instagram, facebook, tiktok, linkedin, threads, whatsapp

Each platform requires its own OAuth app credentials stored in env vars:
  YOUTUBE_CLIENT_ID / YOUTUBE_CLIENT_SECRET
  META_CLIENT_ID    / META_CLIENT_SECRET          (instagram, facebook, threads, whatsapp)
  TIKTOK_CLIENT_ID  / TIKTOK_CLIENT_SECRET
  LINKEDIN_CLIENT_ID / LINKEDIN_CLIENT_SECRET

The app's redirect base URI must also be set:
  OAUTH_REDIRECT_BASE  e.g. https://your-repl.replit.app
  (defaults to REPLIT_DEV_DOMAIN for development)
"""

import os
import json
import secrets
import urllib.parse
from datetime import datetime, timedelta
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select as sa_select, delete as sa_delete

from database import get_async_db
from models import OAuthState, PlatformToken, User
from crypto import encrypt_token

router = APIRouter(prefix="/api/v1/auth", tags=["oauth"])

# ── Helpers ───────────────────────────────────────────────────────────────────

def _redirect_base() -> str:
    base = os.environ.get("OAUTH_REDIRECT_BASE") or os.environ.get("REPLIT_DEV_DOMAIN", "")
    if base and not base.startswith("http"):
        base = f"https://{base}"
    return base.rstrip("/")


def _callback_uri(platform: str) -> str:
    return f"{_redirect_base()}/api/v1/auth/callback/{platform}"


# ── Per-platform OAuth2 config ────────────────────────────────────────────────

def _platform_config(platform: str) -> dict:
    """Return auth_url, token_url, client_id, client_secret, and scopes."""
    base = _redirect_base()

    cfg: dict = {}

    if platform == "youtube":
        cfg = {
            "auth_url":     "https://accounts.google.com/o/oauth2/v2/auth",
            "token_url":    "https://oauth2.googleapis.com/token",
            "client_id":    os.environ.get("YOUTUBE_CLIENT_ID", ""),
            "client_secret": os.environ.get("YOUTUBE_CLIENT_SECRET", ""),
            "scopes": [
                "https://www.googleapis.com/auth/youtube.upload",
                "https://www.googleapis.com/auth/youtube",
                "https://www.googleapis.com/auth/youtube.readonly",
            ],
            "extra_params": {"access_type": "offline", "prompt": "consent"},
        }

    elif platform in ("instagram", "facebook", "threads", "whatsapp"):
        # All Meta platforms share one OAuth app
        scopes = {
            "instagram": [
                "instagram_basic",
                "instagram_content_publish",
                "instagram_manage_comments",
                "pages_read_engagement",
            ],
            "facebook": [
                "pages_manage_posts",
                "pages_read_engagement",
                "publish_video",
            ],
            "threads": [
                "threads_basic",
                "threads_content_publish",
            ],
            "whatsapp": [
                "whatsapp_business_messaging",
                "whatsapp_business_management",
            ],
        }
        cfg = {
            "auth_url":     "https://www.facebook.com/v19.0/dialog/oauth",
            "token_url":    "https://graph.facebook.com/v19.0/oauth/access_token",
            "client_id":    os.environ.get("META_APP_ID", os.environ.get("META_API_ID", "")),
            "client_secret": os.environ.get("META_APP_SECRET", ""),
            "scopes":       scopes.get(platform, []),
            "extra_params": {},
        }

    elif platform == "tiktok":
        cfg = {
            "auth_url":     "https://www.tiktok.com/v2/auth/authorize",
            "token_url":    "https://open.tiktokapis.com/v2/oauth/token/",
            "client_id":    os.environ.get("TIKTOK_CLIENT_ID", ""),
            "client_secret": os.environ.get("TIKTOK_CLIENT_SECRET", ""),
            "scopes":       ["video.upload", "video.publish", "user.info.basic"],
            "extra_params": {},
        }

    elif platform == "linkedin":
        cfg = {
            "auth_url":     "https://www.linkedin.com/oauth/v2/authorization",
            "token_url":    "https://www.linkedin.com/oauth/v2/accessToken",
            "client_id":    os.environ.get("LINKEDIN_CLIENT_ID", ""),
            "client_secret": os.environ.get("LINKEDIN_CLIENT_SECRET", ""),
            "scopes":       ["openid", "profile", "email", "w_member_social"],
            "extra_params": {},
        }

    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Platform '{platform}' does not support OAuth2 connect via this endpoint.",
        )

    if not cfg.get("client_id"):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                f"OAuth2 credentials for '{platform}' are not configured on this server. "
                f"Set the appropriate CLIENT_ID / CLIENT_SECRET environment variables."
            ),
        )

    return cfg


# ── CSRF state helpers ────────────────────────────────────────────────────────

_STATE_TTL_MINUTES = 10


async def _mint_state(user_id: int, platform: str, db: AsyncSession) -> str:
    nonce = secrets.token_urlsafe(32)
    db.add(OAuthState(user_id=user_id, platform=platform, state_nonce=nonce))
    await db.commit()
    return nonce


async def _verify_state(state: str, platform: str, db: AsyncSession) -> OAuthState:
    record = (
        await db.execute(
            sa_select(OAuthState).where(
                OAuthState.state_nonce == state, OAuthState.platform == platform
            )
        )
    ).scalar_one_or_none()
    if not record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or already-used OAuth state. Restart the connect flow.",
        )
    # Enforce TTL
    age = (datetime.utcnow() - record.created_at).total_seconds()
    if age > _STATE_TTL_MINUTES * 60:
        await db.delete(record)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OAuth state expired. Please restart the connect flow.",
        )
    return record


# ── Routes ────────────────────────────────────────────────────────────────────
# `get_current_user` is imported lazily inside each handler to avoid a circular
# import at module load time (main → oauth_router → main).  FastAPI resolves
# `Depends` at request time, so the lazy wrapper below is called then — not
# during module import — which breaks the cycle and keeps `oauth_router`
# importable on its own (e.g. in tests that only need `_postmessage_page`).

from fastapi.security import HTTPBearer as _HTTPBearer, HTTPAuthorizationCredentials as _Creds

_bearer_scheme = _HTTPBearer()


async def _resolve_current_user(
    credentials: _Creds = Depends(_bearer_scheme),
    db: AsyncSession = Depends(get_async_db),
) -> User:
    """Thin lazy proxy for main.get_current_user — same signature, deferred import."""
    from main import get_current_user  # noqa: PLC0415
    return await get_current_user(credentials=credentials, db=db)


@router.get("/connect/{platform}", summary="Initiate OAuth2 platform connection")
async def connect_platform(
    platform: str,
    current_user: User = Depends(_resolve_current_user),
    db: AsyncSession = Depends(get_async_db),
):
    """Generate a signed OAuth2 authorization URL for *platform*.

    The caller should redirect the user's browser to the returned ``auth_url``.
    A CSRF-protection state nonce is minted and stored in ``oauth_states``.
    """
    cfg = _platform_config(platform)
    state = await _mint_state(current_user.id, platform, db)
    redirect_uri = _callback_uri(platform)

    params: dict = {
        "client_id":     cfg["client_id"],
        "redirect_uri":  redirect_uri,
        "response_type": "code",
        "scope":         " ".join(cfg["scopes"]),
        "state":         state,
        **cfg.get("extra_params", {}),
    }

    auth_url = cfg["auth_url"] + "?" + urllib.parse.urlencode(params)
    return {
        "platform":     platform,
        "auth_url":     auth_url,
        "redirect_uri": redirect_uri,
        "info":         f"Redirect the user to auth_url to begin the {platform} OAuth2 flow.",
    }


@router.get(
    "/callback/{platform}",
    response_class=HTMLResponse,
    summary="Handle OAuth2 callback and persist encrypted tokens",
    include_in_schema=False,
)
async def oauth_callback(
    platform: str,
    request: Request,
    db: AsyncSession = Depends(get_async_db),
):
    """Receive the OAuth2 redirect from the platform.

    1. Verify the ``state`` nonce against ``oauth_states`` (CSRF guard).
    2. Exchange the ``code`` for access + refresh tokens via a backend POST.
    3. Encrypt both tokens with AES-256-GCM.
    4. Upsert a ``PlatformToken`` row for the user.
    5. Return a postMessage HTML page that flips the frontend badge to "Connected".
    """
    params = dict(request.query_params)
    code = params.get("code")
    state = params.get("state")
    error = params.get("error")

    if error:
        return _postmessage_page(platform, success=False, error=error)

    if not code or not state:
        return _postmessage_page(platform, success=False, error="Missing code or state parameter.")

    # ── CSRF verification ─────────────────────────────────────────────────────
    try:
        state_record = await _verify_state(state, platform, db)
    except HTTPException as exc:
        return _postmessage_page(platform, success=False, error=exc.detail)

    user_id = state_record.user_id
    cfg = _platform_config(platform)
    redirect_uri = _callback_uri(platform)

    # ── Token exchange ────────────────────────────────────────────────────────
    token_payload: dict = {
        "grant_type":    "authorization_code",
        "code":          code,
        "redirect_uri":  redirect_uri,
        "client_id":     cfg["client_id"],
        "client_secret": cfg["client_secret"],
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                cfg["token_url"],
                data=token_payload,
                headers={"Accept": "application/json"},
            )
        token_data = resp.json()
    except Exception as exc:
        return _postmessage_page(platform, success=False, error=f"Token exchange failed: {exc}")

    if "error" in token_data or "access_token" not in token_data:
        err_msg = token_data.get("error_description") or token_data.get("error") or str(token_data)
        return _postmessage_page(platform, success=False, error=err_msg)

    raw_access  = token_data["access_token"]
    raw_refresh = token_data.get("refresh_token")

    # Calculate expiry timestamp
    expires_in: Optional[int] = token_data.get("expires_in")
    token_expiry: Optional[datetime] = (
        datetime.utcnow() + timedelta(seconds=int(expires_in))
        if expires_in else None
    )

    # ── Fetch platform-specific account / author / user ID ────────────────────
    # Publishers require account_id (Instagram account ID, Facebook page ID,
    # LinkedIn URN, TikTok open_id, YouTube channel ID).  We fetch these from
    # the platform's identity endpoint right after token exchange while we still
    # have the raw (unencrypted) access token.  Failure is non-fatal — the token
    # is still stored and the user can supply account_id manually if needed.
    account_id: Optional[str] = None
    platform_handle: Optional[str] = None
    try:
        async with httpx.AsyncClient(timeout=10.0) as id_client:
            if platform == "youtube":
                r = await id_client.get(
                    "https://www.googleapis.com/youtube/v3/channels",
                    params={"part": "id,snippet", "mine": "true"},
                    headers={"Authorization": f"Bearer {raw_access}"},
                )
                if r.status_code == 200:
                    items = r.json().get("items", [])
                    if items:
                        account_id = items[0].get("id")
                        platform_handle = items[0].get("snippet", {}).get("title")

            elif platform in ("instagram", "threads"):
                # Instagram/Threads Business or Creator account ID
                r = await id_client.get(
                    "https://graph.facebook.com/v19.0/me",
                    params={"fields": "id,name,username", "access_token": raw_access},
                )
                if r.status_code == 200:
                    data = r.json()
                    account_id = data.get("id")
                    platform_handle = data.get("username") or data.get("name")

            elif platform == "facebook":
                # Facebook publishing requires a Page access token.
                # /me/accounts returns all pages managed by this user along with
                # their page-level access tokens.  We take the first page and
                # swap the user token for the page token so publishing works.
                r = await id_client.get(
                    "https://graph.facebook.com/v19.0/me/accounts",
                    params={"access_token": raw_access},
                )
                if r.status_code == 200:
                    pages = r.json().get("data", [])
                    if pages:
                        first = pages[0]
                        account_id = first.get("id")
                        platform_handle = first.get("name")
                        # Replace user token with page-scoped token for publishing
                        page_token = first.get("access_token")
                        if page_token:
                            raw_access = page_token

            elif platform == "linkedin":
                # Fetch the person URN — required as the ugcPosts 'author' field.
                r = await id_client.get(
                    "https://api.linkedin.com/v2/userinfo",
                    headers={"Authorization": f"Bearer {raw_access}"},
                )
                if r.status_code == 200:
                    data = r.json()
                    sub = data.get("sub", "")
                    account_id = sub if sub.startswith("urn:li:") else f"urn:li:person:{sub}" if sub else None
                    platform_handle = data.get("name") or data.get("email")

            elif platform == "tiktok":
                # open_id is required by the TikTok Content Posting API.
                r = await id_client.post(
                    "https://open.tiktokapis.com/v2/user/info/",
                    params={"fields": "open_id,display_name"},
                    headers={"Authorization": f"Bearer {raw_access}",
                             "Content-Type": "application/json"},
                )
                if r.status_code == 200:
                    user_data = r.json().get("data", {}).get("user", {})
                    account_id = user_data.get("open_id")
                    platform_handle = user_data.get("display_name")
    except Exception:
        # Identity fetch failure is non-fatal.  The token is still stored;
        # account_id defaults to None and can be supplied manually.
        pass

    # ── Encrypt tokens before persisting ─────────────────────────────────────
    encrypted_access  = encrypt_token(raw_access)
    encrypted_refresh = encrypt_token(raw_refresh) if raw_refresh else None

    scopes = token_data.get("scope", " ".join(cfg["scopes"]))

    # ── Upsert PlatformToken ──────────────────────────────────────────────────
    existing = (
        await db.execute(
            sa_select(PlatformToken).where(
                PlatformToken.user_id == user_id, PlatformToken.platform == platform
            )
        )
    ).scalar_one_or_none()
    if existing:
        existing.access_token  = encrypted_access
        existing.refresh_token = encrypted_refresh
        existing.account_id    = account_id or existing.account_id  # preserve if refetch failed
        existing.platform_account_handle = platform_handle or existing.platform_account_handle
        existing.token_expiry  = token_expiry
        existing.authorized_scopes = json.dumps(scopes.split() if isinstance(scopes, str) else scopes)
        existing.auto_publish_enabled = True
        existing.connected_at = datetime.utcnow()
    else:
        db.add(PlatformToken(
            user_id=user_id,
            platform=platform,
            access_token=encrypted_access,
            refresh_token=encrypted_refresh,
            account_id=account_id,
            platform_account_handle=platform_handle,
            token_expiry=token_expiry,
            authorized_scopes=json.dumps(scopes.split() if isinstance(scopes, str) else scopes),
            auto_publish_enabled=True,
        ))

    # Consume the state nonce — one-time use
    await db.delete(state_record)
    await db.commit()

    return _postmessage_page(platform, success=True)


# ── postMessage response page ─────────────────────────────────────────────────

def _postmessage_page(platform: str, *, success: bool, error: str = "") -> HTMLResponse:
    """Return an HTML page that delivers the OAuth result to the parent window.

    Two delivery paths are attempted in order:
    1. window.opener.postMessage — works when the OAuth flow ran inside a popup.
       The frontend's onOAuthMessage listener flips the badge to "connected".
       postMessage is restricted to window.location.origin (same domain) rather
       than '*' to prevent cross-origin message injection.
    2. Redirect fallback — used when window.opener is null (popup was blocked and
       the main window was navigated to the OAuth provider instead).  The result
       is appended as ?oauth_result=<JSON> to the AlphaApp route and the browser
       is redirected there.  AlphaApp reads the param on remount via
       readOAuthResultFromUrl() and applies the badge update.

       The target URL is the AlphaApp mockup route (/__mockup/…) because:
       - The FastAPI / handler also preserves query strings and redirects there,
         but targeting it directly skips an extra round-trip.
       - Replit's path-based router (router="path" in .replit) serves __mockup/
         from the Vite workflow on all configured domains, so the redirect lands
         on the correct frontend regardless of which server origin handled the
         OAuth callback.

    Security notes:
    - The ``error`` value originates from the OAuth provider's redirect and is
      HTML-escaped before interpolation to prevent reflected XSS.
    - The JSON payload blob is produced by json.dumps which serialises all values
      as safe JSON literals — no additional escaping is needed for the script context.
    """
    import html as _html

    # HTML-escape the provider-supplied error string before rendering in HTML.
    safe_error_html = _html.escape(error)
    # safe_error_json is handled by json.dumps below.

    payload = json.dumps({
        "type": "ALPHA_OAUTH_RESULT",
        "platform": platform,
        "success": success,
        "error": error,
    })
    # AlphaApp URL — the FastAPI / handler also redirects here (with query string
    # preserved), but we target the route directly to avoid the extra hop.
    alpha_app_route = "/__mockup/preview/alpha-screens/AlphaApp"
    body_content = (
        "<p style='font-size:2rem;'>✅</p><p>Connected! Returning to app…</p>"
        if success else
        f"<p style='font-size:2rem;'>❌</p><p>Connection failed: {safe_error_html}</p>"
    )
    html_page = f"""<!DOCTYPE html>
<html>
<head><title>Connecting…</title></head>
<body style="background:#0f172a;color:#e2e8f0;font-family:sans-serif;display:flex;
             align-items:center;justify-content:center;height:100vh;margin:0;">
  <div style="text-align:center;" id="msg">
    {body_content}
  </div>
  <script>
    var payload = {payload};
    var ALPHA_APP_ROUTE = {json.dumps(alpha_app_route)};
    // Use same-origin target for postMessage instead of '*' to prevent
    // cross-origin message injection.
    var TARGET_ORIGIN = window.location.origin;
    try {{
      if (window.opener && !window.opener.closed) {{
        // Normal popup path: deliver via postMessage then close this window.
        window.opener.postMessage(payload, TARGET_ORIGIN);
        setTimeout(function() {{ window.close(); }}, 1500);
      }} else {{
        // Fallback path: main window was redirected here (popup was blocked).
        // Redirect directly to the AlphaApp route with the result in the query
        // string so AlphaApp can read it on remount via readOAuthResultFromUrl().
        var params = new URLSearchParams({{ oauth_result: JSON.stringify(payload) }});
        window.location.replace(ALPHA_APP_ROUTE + '?' + params.toString());
      }}
    }} catch(e) {{
      // If postMessage throws (cross-origin or null opener), use the redirect.
      var params2 = new URLSearchParams({{ oauth_result: JSON.stringify(payload) }});
      window.location.replace(ALPHA_APP_ROUTE + '?' + params2.toString());
    }}
  </script>
</body>
</html>"""
    return HTMLResponse(content=html_page, status_code=200)
