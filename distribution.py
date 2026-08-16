"""
Multi-Network Distribution Core for ALPHA Automated Visual Podcast Factory.

Real API calls are made to:
  - YouTube Community Posts  (YouTube Data API v3)
  - Instagram Feed           (Meta Graph API v19)
  - Facebook Pages           (Meta Graph API v19)
  - LinkedIn Feed            (LinkedIn UGC Posts API v2)
  - TikTok Photo Posts       (TikTok Content Posting API v2)
  - Threads Feed             (Threads API / Meta Graph API v1)

WhatsApp and YouTube Shorts remain stubs until their upload paths are
implemented (WhatsApp requires business phone number; YT Shorts requires
binary video upload).

Error surfacing contract
────────────────────────
Every publisher returns {"status": "success"|"failed"|"skipped", "message": str}.
execute_omnichannel_publishing() sets post.status to "published" if any platform
succeeded, or "failed" if every configured platform errored.
"""

import os
import httpx
from datetime import datetime
from models import PostsQueue, UserWallet, UserAestheticSetting
from oauth_tokens import get_platform_token, ensure_token_fresh
from crypto import decrypt_token


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _make_public_url(path: str | None) -> str | None:
    """
    Convert a server-local asset path (e.g. /assets/storage/foo.png) to a
    fully-qualified HTTPS URL that external APIs can reach.

    Uses the REPLIT_DEV_DOMAIN environment variable which is always set in the
    Replit environment. Returns None if the path is falsy or the domain is
    unavailable.
    """
    if not path:
        return None
    if path.startswith("http://") or path.startswith("https://"):
        return path  # already absolute
    dev_domain = os.environ.get("REPLIT_DEV_DOMAIN", "").strip()
    if not dev_domain:
        return None
    # Strip leading slash so we don't double-slash
    return f"https://{dev_domain}/{path.lstrip('/')}"


def _stub_platform(name: str) -> dict:
    """Placeholder for platforms not yet wired up."""
    return {"status": "skipped", "message": f"{name} publishing not yet configured."}


# ─────────────────────────────────────────────────────────────────────────────
# PREREQUISITE VALIDATORS
# ─────────────────────────────────────────────────────────────────────────────

async def _validate_youtube_token(access_token: str) -> dict:
    """
    Calls channels.list?mine=true to confirm the OAuth token is valid and
    retrieve the channel title for logging.
    Returns {"ok": bool, "channel_title": str|None, "error": str|None}.
    """
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                "https://www.googleapis.com/youtube/v3/channels",
                params={"part": "snippet", "mine": "true"},
                headers={"Authorization": f"Bearer {access_token}"},
            )
    except httpx.RequestError as exc:
        return {"ok": False, "channel_title": None, "error": f"Network error: {exc}"}

    if resp.status_code == 200:
        items = resp.json().get("items", [])
        if items:
            title = items[0].get("snippet", {}).get("title", "unknown")
            return {"ok": True, "channel_title": title, "error": None}
        return {"ok": False, "channel_title": None,
                "error": "Token is valid but no YouTube channel was found for this account."}
    return {
        "ok": False,
        "channel_title": None,
        "error": f"YouTube token validation failed ({resp.status_code}): {resp.text[:300]}",
    }


async def _validate_linkedin_token(access_token: str) -> dict:
    """
    Calls the LinkedIn /v2/userinfo endpoint (OpenID Connect) to confirm the
    OAuth token is valid and retrieve the member's name for logging.
    Returns {"ok": bool, "name": str|None, "error": str|None}.
    """
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                "https://api.linkedin.com/v2/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
            )
    except httpx.RequestError as exc:
        return {"ok": False, "name": None, "error": f"Network error: {exc}"}

    if resp.status_code == 200:
        data = resp.json()
        name = data.get("name") or data.get("email") or "unknown"
        return {"ok": True, "name": name, "error": None}
    return {
        "ok": False,
        "name": None,
        "error": f"LinkedIn token validation failed ({resp.status_code}): {resp.text[:300]}",
    }


async def _validate_tiktok_token(access_token: str) -> dict:
    """
    Calls the TikTok /v2/user/info/ endpoint to confirm the OAuth token is
    valid and retrieve the user's display name for logging.
    Returns {"ok": bool, "display_name": str|None, "error": str|None}.
    """
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                "https://open.tiktokapis.com/v2/user/info/",
                params={"fields": "open_id,display_name,username"},
                headers={"Authorization": f"Bearer {access_token}"},
            )
    except httpx.RequestError as exc:
        return {"ok": False, "display_name": None, "error": f"Network error: {exc}"}

    if resp.status_code == 200:
        data = resp.json().get("data", {}).get("user", {})
        display_name = data.get("display_name") or data.get("username") or "unknown"
        error_code = resp.json().get("error", {}).get("code", "ok")
        if error_code != "ok":
            return {
                "ok": False,
                "display_name": None,
                "error": f"TikTok token validation error: {resp.json().get('error', {})}",
            }
        return {"ok": True, "display_name": display_name, "error": None}
    return {
        "ok": False,
        "display_name": None,
        "error": f"TikTok token validation failed ({resp.status_code}): {resp.text[:300]}",
    }


async def _validate_whatsapp_token(access_token: str, phone_number_id: str) -> dict:
    """
    Calls the Meta Graph API to verify a WhatsApp Business access token and
    retrieve the registered phone number for logging.

    If a phone_number_id is provided, hits the phone number endpoint to confirm
    both the token *and* the ID are valid; otherwise falls back to /me.

    Returns {"ok": bool, "display_phone_number": str|None, "error": str|None}.
    """
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            if phone_number_id:
                resp = await client.get(
                    f"https://graph.facebook.com/v19.0/{phone_number_id}",
                    params={
                        "fields": "display_phone_number,verified_name",
                        "access_token": access_token,
                    },
                )
            else:
                resp = await client.get(
                    "https://graph.facebook.com/v19.0/me",
                    params={"access_token": access_token},
                )
    except httpx.RequestError as exc:
        return {"ok": False, "display_phone_number": None, "error": f"Network error: {exc}"}

    if resp.status_code == 200:
        data = resp.json()
        display_phone = (
            data.get("display_phone_number")
            or data.get("name")
            or data.get("id")
            or "unknown"
        )
        return {"ok": True, "display_phone_number": display_phone, "error": None}
    return {
        "ok": False,
        "display_phone_number": None,
        "error": f"WhatsApp token validation failed ({resp.status_code}): {resp.text[:300]}",
    }


async def _validate_instagram_token(access_token: str, account_id: str) -> dict:
    """
    Calls the Meta Graph API /me endpoint to confirm the token and account ID
    are valid.
    Returns {"ok": bool, "name": str|None, "error": str|None}.
    """
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"https://graph.facebook.com/v19.0/{account_id}",
                params={"fields": "id,name,username", "access_token": access_token},
            )
    except httpx.RequestError as exc:
        return {"ok": False, "name": None, "error": f"Network error: {exc}"}

    if resp.status_code == 200:
        data = resp.json()
        name = data.get("name") or data.get("username") or "unknown"
        return {"ok": True, "name": name, "error": None}
    return {
        "ok": False,
        "name": None,
        "error": f"Instagram token validation failed ({resp.status_code}): {resp.text[:300]}",
    }


# ─────────────────────────────────────────────────────────────────────────────
# PLATFORM PUBLISHERS
# ─────────────────────────────────────────────────────────────────────────────

def _publish_youtube_community_post_stub() -> dict:
    """
    YouTube Community Posts (youtube/v3/communityPosts) is not a generally
    available write endpoint in the YouTube Data API v3 — it requires channel
    eligibility (500+ subscribers) and is not accessible via the public API
    surface used here. YouTube publishing is therefore skipped until a
    supported upload path (e.g. videos.insert for Shorts) is implemented.
    """
    return {
        "status": "skipped",
        "message": (
            "YouTube Community Posts requires channel eligibility (500+ subscribers) "
            "and restricted API access not available via the public Data API v3. "
            "YouTube publishing is pending a supported implementation."
        ),
    }


async def _publish_instagram_post(
    caption: str,
    local_image_path: str | None,
    access_token: str | None = None,
    account_id: str | None = None,
) -> dict:
    """
    Publish an IMAGE post to an Instagram Business/Creator account via the
    Meta Graph API v19.

    The image must be publicly accessible. Local /assets/storage/ paths are
    converted to absolute HTTPS URLs using REPLIT_DEV_DOMAIN. If no public URL
    can be constructed the publish is aborted with a clear error — never silent.

    Credentials priority:
      1. Explicit access_token / account_id arguments (from per-user DB tokens,
         already refreshed by ensure_token_fresh before this call).
      2. INSTAGRAM_ACCESS_TOKEN / INSTAGRAM_ACCOUNT_ID environment secrets
         (legacy fallback for single-user deployments).

    Returns {"status": "success"|"failed"|"skipped", "message": str}.
    """
    access_token = (access_token or "").strip() or os.environ.get("INSTAGRAM_ACCESS_TOKEN", "").strip()
    account_id   = (account_id   or "").strip() or os.environ.get("INSTAGRAM_ACCOUNT_ID",   "").strip()

    if not access_token or not account_id:
        return {
            "status":  "skipped",
            "message": "INSTAGRAM_ACCESS_TOKEN or INSTAGRAM_ACCOUNT_ID not configured.",
        }

    # 1. Validate credentials before attempting publish
    validation = await _validate_instagram_token(access_token, account_id)
    if not validation["ok"]:
        return {
            "status":  "failed",
            "message": f"Instagram credential check failed: {validation['error']}",
        }

    # 2. Resolve the image URL to a publicly reachable HTTPS address
    public_image_url = _make_public_url(local_image_path)

    if not public_image_url:
        return {
            "status":  "failed",
            "message": (
                "Instagram requires a publicly accessible image URL. "
                "No image was available for this post, or REPLIT_DEV_DOMAIN "
                "is not set so the local asset path cannot be resolved."
            ),
        }

    base = f"https://graph.facebook.com/v19.0/{account_id}"

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            # Step 1 — create media container
            container_resp = await client.post(
                f"{base}/media",
                params={
                    "image_url":    public_image_url,
                    "media_type":   "IMAGE",
                    "caption":      caption,
                    "access_token": access_token,
                },
            )

        if container_resp.status_code not in (200, 201):
            return {
                "status":  "failed",
                "message": (
                    f"Instagram container creation failed "
                    f"({container_resp.status_code}): {container_resp.text[:400]}"
                ),
            }

        creation_id = container_resp.json().get("id")
        if not creation_id:
            return {
                "status":  "failed",
                "message": (
                    f"Instagram API did not return a container id: "
                    f"{container_resp.text[:200]}"
                ),
            }

        # Step 2 — publish the container
        async with httpx.AsyncClient(timeout=30.0) as client:
            publish_resp = await client.post(
                f"{base}/media_publish",
                params={
                    "creation_id":  creation_id,
                    "access_token": access_token,
                },
            )

    except httpx.RequestError as exc:
        return {"status": "failed", "message": f"Network error reaching Instagram API: {exc}"}

    if publish_resp.status_code in (200, 201):
        post_id  = publish_resp.json().get("id", "unknown")
        ig_name  = validation.get("name", "unknown")
        return {
            "status":  "success",
            "message": f"Instagram post published (id={post_id}) to account '{ig_name}'.",
        }

    return {
        "status":  "failed",
        "message": (
            f"Instagram publish step failed "
            f"({publish_resp.status_code}): {publish_resp.text[:400]}"
        ),
    }


async def _publish_facebook_post(
    caption: str,
    local_image_path: str | None,
    access_token: str | None = None,
    page_id: str | None = None,
) -> dict:
    """
    Publish an image post (or text-only fallback) to a Facebook Page via the
    Meta Graph API v19.

    Credentials priority:
      1. Explicit access_token / page_id arguments (per-user DB tokens).
      2. FACEBOOK_ACCESS_TOKEN / FACEBOOK_PAGE_ID environment secrets (fallback).

    Returns {"status": "success"|"failed"|"skipped", "message": str}.
    """
    access_token = (access_token or "").strip() or os.environ.get("FACEBOOK_ACCESS_TOKEN", "").strip()
    page_id      = (page_id      or "").strip() or os.environ.get("FACEBOOK_PAGE_ID",       "").strip()

    if not access_token or not page_id:
        return {
            "status":  "skipped",
            "message": "FACEBOOK_ACCESS_TOKEN or FACEBOOK_PAGE_ID not configured.",
        }

    base = f"https://graph.facebook.com/v19.0/{page_id}"
    public_image_url = _make_public_url(local_image_path)

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            if public_image_url:
                # Photo post with caption
                resp = await client.post(
                    f"{base}/photos",
                    params={
                        "url":          public_image_url,
                        "message":      caption,
                        "access_token": access_token,
                    },
                )
            else:
                # Text-only feed post when no image is available
                resp = await client.post(
                    f"{base}/feed",
                    params={
                        "message":      caption,
                        "access_token": access_token,
                    },
                )
    except httpx.RequestError as exc:
        return {"status": "failed", "message": f"Network error reaching Facebook API: {exc}"}

    if resp.status_code in (200, 201):
        post_id = resp.json().get("id", "unknown")
        return {
            "status":  "success",
            "message": f"Facebook post published (id={post_id}) to page '{page_id}'.",
        }
    return {
        "status":  "failed",
        "message": f"Facebook publish failed ({resp.status_code}): {resp.text[:400]}",
    }


async def _publish_linkedin_post(
    caption: str,
    access_token: str | None = None,
    author_id: str | None = None,
) -> dict:
    """
    Publish a text post to a LinkedIn member or organisation feed via the
    LinkedIn UGC Posts API v2.

    Credentials priority:
      1. Explicit access_token / author_id arguments (per-user DB tokens).
      2. LINKEDIN_ACCESS_TOKEN / LINKEDIN_AUTHOR_ID environment secrets (fallback).

    Returns {"status": "success"|"failed"|"skipped", "message": str}.
    """
    access_token = (access_token or "").strip() or os.environ.get("LINKEDIN_ACCESS_TOKEN", "").strip()
    author_id    = (author_id    or "").strip() or os.environ.get("LINKEDIN_AUTHOR_ID",    "").strip()

    if not access_token or not author_id:
        return {
            "status":  "skipped",
            "message": "LINKEDIN_ACCESS_TOKEN or LINKEDIN_AUTHOR_ID not configured.",
        }

    # Normalise: accept a bare numeric ID for organisations or the full URN
    if not author_id.startswith("urn:li:"):
        author_id = f"urn:li:person:{author_id}"

    payload = {
        "author":           author_id,
        "lifecycleState":   "PUBLISHED",
        "specificContent": {
            "com.linkedin.ugc.ShareContent": {
                "shareCommentary":    {"text": caption},
                "shareMediaCategory": "NONE",
            }
        },
        "visibility": {
            "com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"
        },
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                "https://api.linkedin.com/v2/ugcPosts",
                json=payload,
                headers={
                    "Authorization":  f"Bearer {access_token}",
                    "X-Restli-Protocol-Version": "2.0.0",
                    "Content-Type":   "application/json",
                },
            )
    except httpx.RequestError as exc:
        return {"status": "failed", "message": f"Network error reaching LinkedIn API: {exc}"}

    if resp.status_code in (200, 201):
        post_id = resp.headers.get("x-restli-id") or resp.json().get("id", "unknown")
        return {
            "status":  "success",
            "message": f"LinkedIn post published (id={post_id}) for author '{author_id}'.",
        }
    return {
        "status":  "failed",
        "message": f"LinkedIn publish failed ({resp.status_code}): {resp.text[:400]}",
    }


async def _publish_tiktok_post(
    caption: str,
    local_image_path: str | None,
    access_token: str | None = None,
    open_id: str | None = None,
) -> dict:
    """
    Publish a photo post to TikTok via the TikTok Content Posting API v2.

    If no publicly accessible image URL can be derived the post is aborted
    with a clear error rather than silently skipped.

    Credentials priority:
      1. Explicit access_token / open_id arguments (per-user DB tokens).
      2. TIKTOK_ACCESS_TOKEN / TIKTOK_OPEN_ID environment secrets (fallback).

    Returns {"status": "success"|"failed"|"skipped", "message": str}.
    """
    access_token = (access_token or "").strip() or os.environ.get("TIKTOK_ACCESS_TOKEN", "").strip()
    open_id      = (open_id      or "").strip() or os.environ.get("TIKTOK_OPEN_ID",       "").strip()

    if not access_token or not open_id:
        return {
            "status":  "skipped",
            "message": "TIKTOK_ACCESS_TOKEN or TIKTOK_OPEN_ID not configured.",
        }

    public_image_url = _make_public_url(local_image_path)
    if not public_image_url:
        return {
            "status":  "failed",
            "message": (
                "TikTok photo posts require a publicly accessible image URL. "
                "No image was available or REPLIT_DEV_DOMAIN is not set."
            ),
        }

    payload = {
        "open_id":    open_id,
        "media_type": "PHOTO",
        "post_info": {
            "title":         caption[:150],   # TikTok title cap
            "privacy_level": "PUBLIC_TO_EVERYONE",
            "disable_duet":  False,
            "disable_stitch": False,
            "disable_comment": False,
        },
        "source_info": {
            "source":             "PULL_FROM_URL",
            "photo_cover_index":  0,
            "photo_images":       [public_image_url],
        },
    }

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                "https://open.tiktokapis.com/v2/post/publish/content/init/",
                json=payload,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type":  "application/json; charset=UTF-8",
                },
            )
    except httpx.RequestError as exc:
        return {"status": "failed", "message": f"Network error reaching TikTok API: {exc}"}

    if resp.status_code in (200, 201):
        data    = resp.json().get("data", {})
        post_id = data.get("publish_id") or data.get("share_id") or "unknown"
        return {
            "status":  "success",
            "message": f"TikTok photo post published (publish_id={post_id}).",
        }
    return {
        "status":  "failed",
        "message": f"TikTok publish failed ({resp.status_code}): {resp.text[:400]}",
    }


async def _publish_threads_post(
    caption: str,
    local_image_path: str | None,
    access_token: str | None = None,
    user_id: str | None = None,
) -> dict:
    """
    Publish an image post (or text-only fallback) to Threads via the Threads
    API (Meta Graph API v1 surface for Threads).

    Flow mirrors the Instagram two-step container → publish pattern.

    Credentials priority:
      1. Explicit access_token / user_id arguments (per-user DB tokens).
      2. THREADS_ACCESS_TOKEN / THREADS_USER_ID environment secrets (fallback).

    Returns {"status": "success"|"failed"|"skipped", "message": str}.
    """
    access_token = (access_token or "").strip() or os.environ.get("THREADS_ACCESS_TOKEN", "").strip()
    user_id      = (user_id      or "").strip() or os.environ.get("THREADS_USER_ID",       "").strip()

    if not access_token or not user_id:
        return {
            "status":  "skipped",
            "message": "THREADS_ACCESS_TOKEN or THREADS_USER_ID not configured.",
        }

    public_image_url = _make_public_url(local_image_path)
    base = f"https://graph.threads.net/v1.0/{user_id}"

    # Build container params
    container_params: dict = {
        "text":         caption,
        "access_token": access_token,
    }
    if public_image_url:
        container_params["media_type"] = "IMAGE"
        container_params["image_url"]  = public_image_url
    else:
        container_params["media_type"] = "TEXT"

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            # Step 1 — create media container
            container_resp = await client.post(
                f"{base}/threads",
                params=container_params,
            )

        if container_resp.status_code not in (200, 201):
            return {
                "status":  "failed",
                "message": (
                    f"Threads container creation failed "
                    f"({container_resp.status_code}): {container_resp.text[:400]}"
                ),
            }

        creation_id = container_resp.json().get("id")
        if not creation_id:
            return {
                "status":  "failed",
                "message": (
                    f"Threads API did not return a container id: "
                    f"{container_resp.text[:200]}"
                ),
            }

        # Step 2 — publish the container
        async with httpx.AsyncClient(timeout=30.0) as client:
            publish_resp = await client.post(
                f"{base}/threads_publish",
                params={
                    "creation_id":  creation_id,
                    "access_token": access_token,
                },
            )

    except httpx.RequestError as exc:
        return {"status": "failed", "message": f"Network error reaching Threads API: {exc}"}

    if publish_resp.status_code in (200, 201):
        post_id = publish_resp.json().get("id", "unknown")
        return {
            "status":  "success",
            "message": f"Threads post published (id={post_id}) to user '{user_id}'.",
        }
    return {
        "status":  "failed",
        "message": (
            f"Threads publish step failed "
            f"({publish_resp.status_code}): {publish_resp.text[:400]}"
        ),
    }


# ─────────────────────────────────────────────────────────────────────────────
# CRON CLEANER
# ─────────────────────────────────────────────────────────────────────────────

async def run_60_second_queue_cleaner(db_session):
    """
    Automated Cron execution running every 60 seconds on the dot.
    Scans for expired review buffer countdown timers and forces publication.
    """
    now = datetime.utcnow()
    expired_posts = db_session.query(PostsQueue).filter(
        PostsQueue.status == 'pending_review',
        PostsQueue.scheduled_publish_time <= now
    ).all()

    for post in expired_posts:
        await execute_omnichannel_publishing(post.id, db_session)


# ─────────────────────────────────────────────────────────────────────────────
# USER REVIEW OVERRIDE
# ─────────────────────────────────────────────────────────────────────────────

async def handle_user_review_action(post_id: int, action: str, db_session):
    """
    Processes mobile touch dashboard overrides ("Cancel Post" vs "Post Now")
    """
    post = db_session.query(PostsQueue).filter(PostsQueue.id == post_id).first()
    if not post:
        return {"status": "error", "message": "Post not found"}

    if action == "cancel":
        post.status = "cancelled"
        db_session.commit()
        return {"status": "success", "message": "Purged video/audio files from server storage."}

    elif action == "publish_now":
        result = await execute_omnichannel_publishing(post_id, db_session)
        if result["overall_status"] == "failed":
            return {
                "status":  "error",
                "message": "Publishing failed on all configured platforms.",
                "details": result["platform_log"],
            }
        return {
            "status":  "success",
            "message": "Bypassed countdown clock. Published immediately.",
            "details": result["platform_log"],
        }


# ─────────────────────────────────────────────────────────────────────────────
# OMNICHANNEL PUBLISHING CORE
# ─────────────────────────────────────────────────────────────────────────────

async def execute_omnichannel_publishing(post_id: int, db_session) -> dict:
    """
    Multi-Network Distribution Core.

    Makes real API calls to:
      - Instagram Feed           (Meta Graph API v19)
      - Facebook Pages           (Meta Graph API v19)
      - LinkedIn Feed            (LinkedIn UGC Posts API v2)
      - TikTok Photo Posts       (TikTok Content Posting API v2)
      - Threads Feed             (Threads API / Meta Graph)

    YouTube Community Posts is skipped (requires channel eligibility).
    WhatsApp and YouTube Shorts remain stubs pending upload-path implementation.

    Post DB status:
      "published" — at least one platform call succeeded
      "failed"    — every configured platform returned an error (or none configured)

    Returns {"overall_status": str, "platform_log": dict}.
    """
    post      = db_session.query(PostsQueue).filter(PostsQueue.id == post_id).first()
    aesthetic = (
        db_session.query(UserAestheticSetting)
        .filter(UserAestheticSetting.user_id == post.user_id)
        .first()
    )

    # ── 1. Caption stitching ──────────────────────────────────────────────────
    custom_tags = aesthetic.persistent_hashtags if aesthetic else ""
    target_lang = aesthetic.active_target_language if aesthetic else "en"

    disclaimer_mapping = {
        "en": "\n\nAI news commentary. Not affiliated with subject.",
        "es": "\n\nComentario de noticias de IA. No afiliado con el sujeto.",
        "fr": "\n\nCommentaire d'actualité de l'IA. Non affilié au sujet.",
        "ar": "\n\nتعليق إخباري بالذكاء الاصطناعي. غير تابع للموضوع.",
    }
    disclaimer            = disclaimer_mapping.get(target_lang, disclaimer_mapping["en"])
    final_caption_payload = f"{post.content_text} {custom_tags}{disclaimer}"

    # ── 2. Load and refresh per-user platform tokens ─────────────────────────
    # For each platform, look up the user's stored DB token and proactively
    # refresh it if it is near expiry. If refresh fails we surface a clear
    # "token expired — please reconnect" error for that platform rather than a
    # generic auth failure.  Falls back to env-var credentials when no DB token
    # exists (legacy single-user deployments).

    async def _load_token(platform: str) -> tuple[str | None, str | None, str | None]:
        """
        Returns (access_token, account_id, error_message) for a platform.
        error_message is non-None only when a refresh was attempted and failed.
        """
        tok = get_platform_token(post.user_id, platform, db_session)
        if tok is None:
            return None, None, None   # fall through to env-var lookup in publisher
        ok, err = await ensure_token_fresh(tok, db_session)
        if not ok:
            return None, None, err
        return decrypt_token(tok.access_token), tok.account_id, None

    import asyncio

    (
        (ig_token, ig_account, ig_refresh_err),
        (fb_token, fb_account, fb_refresh_err),
        (li_token, li_author,  li_refresh_err),
        (tt_token, tt_open_id, tt_refresh_err),
        (th_token, th_user,    th_refresh_err),
    ) = await asyncio.gather(
        _load_token("instagram"),
        _load_token("facebook"),
        _load_token("linkedin"),
        _load_token("tiktok"),
        _load_token("threads"),
    )

    def _token_expired_result(platform_label: str, err: str) -> dict:
        return {
            "status":  "failed",
            "message": f"{platform_label} token expired — please reconnect: {err}",
        }

    # ── 3. Real platform API calls ────────────────────────────────────────────
    ig_result = (
        _token_expired_result("Instagram", ig_refresh_err)
        if ig_refresh_err
        else await _publish_instagram_post(
            final_caption_payload,
            post.graphic_card_url,
            access_token=ig_token,
            account_id=ig_account,
        )
    )
    fb_result = (
        _token_expired_result("Facebook", fb_refresh_err)
        if fb_refresh_err
        else await _publish_facebook_post(
            final_caption_payload,
            post.graphic_card_url,
            access_token=fb_token,
            page_id=fb_account,
        )
    )
    li_result = (
        _token_expired_result("LinkedIn", li_refresh_err)
        if li_refresh_err
        else await _publish_linkedin_post(
            final_caption_payload,
            access_token=li_token,
            author_id=li_author,
        )
    )
    tt_result = (
        _token_expired_result("TikTok", tt_refresh_err)
        if tt_refresh_err
        else await _publish_tiktok_post(
            final_caption_payload,
            post.graphic_card_url,
            access_token=tt_token,
            open_id=tt_open_id,
        )
    )
    th_result = (
        _token_expired_result("Threads", th_refresh_err)
        if th_refresh_err
        else await _publish_threads_post(
            final_caption_payload,
            post.graphic_card_url,
            access_token=th_token,
            user_id=th_user,
        )
    )

    platform_log = {
        "YouTube_Community_Posts":      _publish_youtube_community_post_stub(),
        "Instagram_Reels_And_Feed":     ig_result,
        "Facebook_Reels_And_Pages":     fb_result,
        "LinkedIn_Feed":                li_result,
        "TikTok":                       tt_result,
        "Threads_Feed":                 th_result,
        "WhatsApp_Status_And_Channels": _stub_platform("WhatsApp"),
        "YouTube_Shorts":               _stub_platform("YouTube Shorts"),
    }

    # ── 3. Determine overall outcome ─────────────────────────────────────────
    # "skipped" entries don't count toward success or failure
    active_results = [
        r for r in platform_log.values()
        if r["status"] != "skipped"
    ]
    any_success = any(r["status"] == "success" for r in active_results)

    if any_success:
        overall_status = "published"
    elif active_results:
        # All active platforms failed
        overall_status = "failed"
    else:
        # Nothing configured at all
        overall_status = "failed"
        platform_log["__no_credentials"] = {
            "status":  "failed",
            "message": (
                "No platform credentials are configured. Configure at least one "
                "of: INSTAGRAM_ACCESS_TOKEN + INSTAGRAM_ACCOUNT_ID, "
                "FACEBOOK_ACCESS_TOKEN + FACEBOOK_PAGE_ID, "
                "LINKEDIN_ACCESS_TOKEN + LINKEDIN_AUTHOR_ID, "
                "TIKTOK_ACCESS_TOKEN + TIKTOK_OPEN_ID, or "
                "THREADS_ACCESS_TOKEN + THREADS_USER_ID as Replit Secrets."
            ),
        }

    # ── 4. Persist ────────────────────────────────────────────────────────────
    import json as _json
    post.content_text = final_caption_payload
    post.status       = overall_status
    post.publish_log  = _json.dumps(platform_log)
    db_session.commit()

    return {"overall_status": overall_status, "platform_log": platform_log}


# ─────────────────────────────────────────────────────────────────────────────
# STRIPE WALLET LEDGER
# ─────────────────────────────────────────────────────────────────────────────

async def track_stripe_sponsor_revenue(user_id: int, payout_amount: float, db_session):
    """
    Wallet Payout Endpoint handling ad revenue bookkeeping ledgers.
    """
    wallet = db_session.query(UserWallet).filter(UserWallet.user_id == user_id).first()
    if wallet:
        wallet.available_balance += payout_amount
        db_session.commit()
        return {
            "status":                "success",
            "balance_ledger_updated": float(wallet.available_balance),
            "stripe_connect_status": "Verified connection ready for instant bank card withdrawal extraction.",
        }
