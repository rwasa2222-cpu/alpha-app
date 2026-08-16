"""Asynchronous background worker — APScheduler autopilot engine.

Two jobs run continuously from FastAPI startup:

┌─────────────────────────────────────────────────────────────────────────────┐
│ JOB 1 — Hourly Omnichannel Automation  (cron: minute=0, every UTC hour)    │
│                                                                             │
│  For every user whose content_schedule_time hour matches the current hour:  │
│  1. Omnichannel Scraper   → aggregate trending topics + celebrity signals    │
│  2. NVIDIA Nemotron       → generate title, caption, image prompt           │
│  3. Content Safety Filter → validate AI output before persisting            │
│  4. Ad Rotator            → weave active sponsor text into narration        │
│  5. Dual-Render Engine    → image card (Ideogram/Pillow) OR short video     │
│                             (Voicebox TTS + FFmpeg stub) based on mix %     │
│  6. Persistence           → insert PostsQueue row status='pending_review'   │
│                             with scheduled_publish_time = now + buffer_mins │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ JOB 2 — 60-Second Queue Cleaner  (interval: every 60 seconds)              │
│                                                                             │
│  Scans posts_queue for pending_review rows whose scheduled_publish_time     │
│  has elapsed, then auto-publishes via execute_omnichannel_publishing.       │
└─────────────────────────────────────────────────────────────────────────────┘

Lifecycle (called from main.py lifespan):
    from worker import start_scheduler, stop_scheduler
    start_scheduler()   # inside async lifespan startup
    ...
    stop_scheduler()    # inside async lifespan shutdown
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta
from typing import Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from models import (
    SessionLocal,
    User,
    UserAestheticSetting,
    UserSelectedSource,
    PostsQueue,
    Advertisement,
)
from tasks import (
    scrape_omnichannel_news_trends,
    call_nemotron_ai_writer,
    generate_ideogram_background,
    open_source_image_compositor,
    synthesize_voice_audio,
)
from distribution import run_60_second_queue_cleaner

logger = logging.getLogger("alpha.worker")
_scheduler: Optional[AsyncIOScheduler] = None


# ── Content safety filter ─────────────────────────────────────────────────────

_BLOCKED_TERMS = frozenset([
    "violence", "explicit", "nsfw", "hate speech", "self-harm",
])

def _passes_safety_check(title: str, caption: str) -> bool:
    """Lightweight keyword safety gate before persisting AI-generated content."""
    combined = (title + " " + caption).lower()
    return not any(term in combined for term in _BLOCKED_TERMS)


# ── Ad rotator ────────────────────────────────────────────────────────────────

def _weave_ad_into_script(script: str, user_id: int, db) -> str:
    """Append the first active sponsor's offer text to the end of the narration."""
    now = datetime.utcnow()
    ad = (
        db.query(Advertisement)
        .filter(
            Advertisement.user_id == user_id,
            Advertisement.is_active == True,            # noqa: E712
            (Advertisement.start_date.is_(None)) | (Advertisement.start_date <= now),
            (Advertisement.end_date.is_(None))   | (Advertisement.end_date   >= now),
        )
        .first()
    )
    if not ad or not ad.sponsor_services_text:
        return script
    sponsor = ad.sponsor_name or "our sponsor"
    return (
        script
        + f"\n\n[Sponsored] This episode is brought to you by {sponsor}. "
        + ad.sponsor_services_text.strip()
    )


# ── FFmpeg short-video stub ───────────────────────────────────────────────────

def _compose_short_video(
    audio_path: str,
    image_path: str,
    brand_colors: list[str],
    user_id: int,
) -> str:
    """Simulate FFmpeg video compilation.

    In production, replace with a real subprocess call:
        subprocess.run([
            "ffmpeg", "-loop", "1", "-i", image_path,
            "-i", audio_path, "-c:v", "libx264", "-tune", "stillimage",
            "-c:a", "aac", "-b:a", "192k", "-pix_fmt", "yuv420p",
            "-shortest", output_path
        ], check=True)
    """
    output_path = f"assets/storage/short_video_{user_id}.mp4"
    os.makedirs("assets/storage", exist_ok=True)
    logger.info(
        f"[FFmpeg] Stub: would compile {image_path} + {audio_path} → {output_path}"
    )
    # Return path — in prod this file would be created by ffmpeg
    return f"/assets/storage/short_video_{user_id}.mp4"


# ── Dual-render engine ────────────────────────────────────────────────────────

async def _dual_render(
    *,
    user_id: int,
    image_mode: str,
    image_prompt: str,
    hex_colors: list[str],
    template: str,
    title_hook: str,
    caption: str,
    voice_id: str,
    media_mix: int,
) -> tuple[str, Optional[str]]:
    """Route to image card or short-video pipeline based on media_mix percentage.

    Returns (graphic_card_url, voice_audio_url).
    voice_audio_url is None for image-only posts when voice synthesis is skipped.
    """
    # ── Image asset ───────────────────────────────────────────────────────────
    img_filename = f"user_post_{user_id}.png"
    if image_mode == "ai_generation":
        graphic_url = await generate_ideogram_background(
            prompt=image_prompt,
            filename=img_filename,
        )
    else:
        graphic_url = open_source_image_compositor(
            hex_colors, title_hook, template, image_mode, img_filename
        )

    # ── Audio / video ─────────────────────────────────────────────────────────
    narration = f"{title_hook}. {caption}"
    audio_filename = f"voicebox_synth_{user_id}.mp3"

    if media_mix > 50:
        # Short-video branch: synthesise voice + compile with FFmpeg
        audio_url = await synthesize_voice_audio(
            text=narration,
            voice_id=voice_id,
            filename=audio_filename,
        )
        # Replace graphic_url with the compiled video path
        graphic_url = _compose_short_video(
            audio_path=f"assets/audio/{audio_filename}",
            image_path=graphic_url.lstrip("/"),
            brand_colors=hex_colors,
            user_id=user_id,
        )
    else:
        # Image-card branch: synthesise voice for the audio track only
        try:
            audio_url = await synthesize_voice_audio(
                text=narration,
                voice_id=voice_id,
                filename=audio_filename,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                f"[Render] Voice synthesis non-fatal for user_id={user_id}: {exc}"
            )
            audio_url = None

    return graphic_url, audio_url


# ── Celebrity signal aggregator ───────────────────────────────────────────────

def _build_trend_query(niche: str, celebrities: list[str]) -> str:
    """Combine niche + celebrity tracking chips into a richer trend query string."""
    parts = [niche]
    if celebrities:
        parts.append("Tracking: " + ", ".join(celebrities[:10]))
    return " | ".join(parts)


# ── Per-user pipeline ─────────────────────────────────────────────────────────

async def _run_pipeline_for_user(user: User, db) -> None:
    """Full content pipeline for one user: scrape → AI → render → ad-inject → persist."""
    # ── Load settings ─────────────────────────────────────────────────────────
    settings: Optional[UserAestheticSetting] = (
        db.query(UserAestheticSetting)
        .filter(UserAestheticSetting.user_id == user.id)
        .first()
    )

    niche      = (settings.chosen_niche              if settings else None) or "General"
    target_lang= (settings.active_target_language    if settings else None) or "en"
    voice_id   = (settings.voice_id                  if settings else None) or "en_us_m_deep"
    image_mode = (settings.image_mode                if settings else None) or "ai_generation"
    template   = (settings.visual_podcast_template   if settings else None) or "minimalist"
    media_mix  = (settings.media_mix_video_percentage if settings else 50) or 50

    try:
        hex_colors = json.loads(settings.hex_colors) if settings and settings.hex_colors else []
    except (json.JSONDecodeError, TypeError):
        hex_colors = []
    if not hex_colors:
        hex_colors = ["#0F172A"]

    media_type = "automated_short_video" if media_mix > 50 else "image_card"

    # ── Celebrity tracking chips from UserSelectedSource ──────────────────────
    tracking_rows = (
        db.query(UserSelectedSource)
        .filter(UserSelectedSource.user_id == user.id)
        .all()
    )
    celebrities = [r.celebrity_name for r in tracking_rows if r.celebrity_name]

    logger.info(
        f"[Pipeline] user_id={user.id} niche='{niche}' lang={target_lang} "
        f"media={media_type} template={template} "
        f"celebrities={celebrities[:5]}"
    )

    # ── Step 1: Omnichannel trend scraper ─────────────────────────────────────
    trend_query = _build_trend_query(niche, celebrities)
    try:
        raw_trends = await scrape_omnichannel_news_trends(trend_query)
    except Exception as exc:  # noqa: BLE001
        logger.error(f"[Pipeline] Trend scraper failed for user_id={user.id}: {exc}")
        return

    # ── Step 2: NVIDIA Nemotron AI writer ─────────────────────────────────────
    try:
        title_hook, caption, image_prompt = await call_nemotron_ai_writer(
            raw_trends, target_lang
        )
    except Exception as exc:  # noqa: BLE001
        logger.error(f"[Pipeline] Nemotron failed for user_id={user.id}: {exc}")
        return

    # ── Step 3: Content safety filter ─────────────────────────────────────────
    if not _passes_safety_check(title_hook, caption):
        logger.warning(
            f"[Pipeline] user_id={user.id} — content blocked by safety filter. Skipping."
        )
        return

    # ── Step 4: Dual-render engine ────────────────────────────────────────────
    try:
        graphic_url, audio_url = await _dual_render(
            user_id=user.id,
            image_mode=image_mode,
            image_prompt=image_prompt,
            hex_colors=hex_colors,
            template=template,
            title_hook=title_hook,
            caption=caption,
            voice_id=voice_id,
            media_mix=media_mix,
        )
    except Exception as exc:  # noqa: BLE001
        logger.error(f"[Pipeline] Render engine failed for user_id={user.id}: {exc}")
        return

    # ── Step 5: Ad rotator ────────────────────────────────────────────────────
    final_text = _weave_ad_into_script(caption, user.id, db)

    # ── Step 6: Persist to posts_queue ───────────────────────────────────────
    buffer_minutes = user.review_buffer_minutes or 15
    scheduled_at = datetime.utcnow() + timedelta(minutes=buffer_minutes)

    post = PostsQueue(
        user_id=user.id,
        episode_title=title_hook,
        content_text=final_text,
        graphic_card_url=graphic_url,
        voice_audio_url=audio_url,
        media_type=media_type,
        status="pending_review",
        scheduled_publish_time=scheduled_at,
    )
    db.add(post)
    db.commit()
    db.refresh(post)

    logger.info(
        f"[Pipeline] user_id={user.id} — post_id={post.id} queued. "
        f"Auto-publish at {scheduled_at.isoformat()} UTC (+{buffer_minutes}m review buffer)."
    )


# ── Job 1: Hourly automation ──────────────────────────────────────────────────

async def _run_hourly_automation() -> None:
    """Fire the full pipeline for every user whose scheduled hour matches now (UTC)."""
    current_hour_prefix = f"{datetime.utcnow().hour:02d}:"   # e.g. "09:"
    db = SessionLocal()
    try:
        eligible = (
            db.query(User)
            .filter(User.content_schedule_time.like(f"{current_hour_prefix}%"))
            .all()
        )
        logger.info(
            f"[Hourly] UTC hour={datetime.utcnow().hour:02d} — "
            f"{len(eligible)} user(s) scheduled."
        )
        for user in eligible:
            try:
                await _run_pipeline_for_user(user, db)
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    f"[Hourly] Pipeline error for user_id={user.id}: {exc}",
                    exc_info=True,
                )
    except Exception as exc:  # noqa: BLE001
        logger.error(f"[Hourly] Fatal error in automation loop: {exc}", exc_info=True)
    finally:
        db.close()


# ── Job 2: 60-second queue cleaner ───────────────────────────────────────────

async def _run_queue_cleaner() -> None:
    """Auto-publish pending_review posts whose review window has elapsed."""
    db = SessionLocal()
    try:
        await run_60_second_queue_cleaner(db)
    except Exception as exc:  # noqa: BLE001
        logger.error(f"[Cleaner] Error: {exc}", exc_info=True)
    finally:
        db.close()


# ── Dev trigger: manually fire the hourly job for one user ───────────────────

async def trigger_pipeline_for_user(user_id: int) -> dict:
    """Manually invoke the full pipeline for a single user (dev/test use).

    Returns a status dict suitable for a diagnostic API endpoint.
    """
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return {"status": "error", "detail": f"User {user_id} not found."}
        before_count = db.query(PostsQueue).filter(PostsQueue.user_id == user_id).count()
        await _run_pipeline_for_user(user, db)
        after_count = db.query(PostsQueue).filter(PostsQueue.user_id == user_id).count()
        return {
            "status": "ok",
            "user_id": user_id,
            "posts_created": after_count - before_count,
        }
    except Exception as exc:  # noqa: BLE001
        logger.error(f"[Trigger] Error for user_id={user_id}: {exc}", exc_info=True)
        return {"status": "error", "detail": str(exc)}
    finally:
        db.close()


# ── Scheduler lifecycle ───────────────────────────────────────────────────────

def start_scheduler() -> None:
    """Create and start the APScheduler AsyncIOScheduler.

    Safe to call multiple times — idempotent if already running (handles hot-reload).
    Must be called from within an active asyncio event loop (e.g. FastAPI lifespan).
    """
    global _scheduler
    if _scheduler and _scheduler.running:
        logger.debug("[Worker] Scheduler already running — skipping start.")
        return

    _scheduler = AsyncIOScheduler(timezone="UTC")

    _scheduler.add_job(
        _run_hourly_automation,
        trigger=CronTrigger(minute=0, timezone="UTC"),
        id="hourly_automation",
        name="Hourly omnichannel content pipeline",
        replace_existing=True,
        misfire_grace_time=300,   # tolerate up to 5-min late starts
        max_instances=1,          # never run two hourly jobs concurrently
    )

    _scheduler.add_job(
        _run_queue_cleaner,
        trigger=IntervalTrigger(seconds=60),
        id="queue_cleaner",
        name="60-second queue cleaner / auto-publisher",
        replace_existing=True,
        misfire_grace_time=30,
        max_instances=1,
    )

    _scheduler.start()
    logger.info(
        "[Worker] APScheduler started. "
        "Jobs: hourly_automation (cron minute=0), queue_cleaner (interval 60s)."
    )


def stop_scheduler() -> None:
    """Gracefully shut down the scheduler on application exit."""
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        logger.info("[Worker] APScheduler stopped.")
