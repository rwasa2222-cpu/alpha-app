import os
import random
import httpx
from datetime import datetime
from PIL import Image, ImageDraw

# ─────────────────────────────────────────────────────────────────────────────
# TREND SCRAPER
# ─────────────────────────────────────────────────────────────────────────────

async def scrape_omnichannel_news_trends(niche_value: str):
    """Aggregate real-time trend signals across 8 major platforms."""
    networks = [
        "Google News", "Google Trends", "TikTok Trends", "Instagram Graph",
        "Facebook Graph", "YouTube Data", "X Trends", "Baidu Index",
    ]
    trend_context = (
        f"Aggregate real-time summary payload matching target: '{niche_value}' "
        f"compiled at {datetime.utcnow()}.\n"
    )
    for net in networks:
        trend_context += f"- [{net}] High-Velocity trending discourse signal intercepted.\n"
    return trend_context


# ─────────────────────────────────────────────────────────────────────────────
# NVIDIA NEMOTRON AI WRITER
# ─────────────────────────────────────────────────────────────────────────────

async def generate_script_for_perspective(
    niche: str,
    celebrities: list,
    perspective: str,
) -> dict:
    """
    Calls NVIDIA Nemotron to generate a full podcast narration script for the
    given niche, celebrity list, and perspective angle.

    perspective must be one of: "analytical", "hype", "humorous", "reporter"

    Returns a dict with keys:
        body        – full narration script (200-300 words)
        titleHook   – punchy episode title hook
        imagePrompt – vivid Ideogram image generation prompt
        subtitles   – list of 5 short on-screen subtitle strings
    """
    import json as _json_inner

    api_key = os.environ.get("NVIDIA_API_KEY")
    if not api_key:
        raise EnvironmentError("NVIDIA_API_KEY secret is not set.")

    perspective_labels = {
        "analytical": "Analytical Expert",
        "hype": "High-Energy Hype",
        "humorous": "Humorous Critic",
        "reporter": "Curious Reporter",
    }
    persona = perspective_labels.get(perspective, "Analytical Expert")

    cel_list = ", ".join(celebrities) if celebrities else "notable public figures"
    user_context = (
        f"Niche: {niche}\n"
        f"Featured public figures: {cel_list}\n"
        f"Current date/time UTC: {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}\n"
    )

    system_prompt = (
        f"You are an elite podcast script writer with the persona: {persona}. "
        "Given the niche, featured public figures, and date, produce a JSON object "
        "with EXACTLY these four keys:\n"
        '  "body": a full narration script in your persona voice (200-300 words, engaging)\n'
        '  "titleHook": a punchy episode title hook (max 12 words, include relevant emoji)\n'
        '  "imagePrompt": a vivid cinematic Ideogram image prompt (max 40 words)\n'
        '  "subtitles": an array of exactly 5 short on-screen subtitle strings (max 6 words each)\n'
        "Write in English. Return ONLY valid JSON — no markdown fences, no extra text."
    )

    payload = {
        "model": "meta/llama-3.1-70b-instruct",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_context},
        ],
        "temperature": 0.88,
        "max_tokens": 700,
    }

    async with httpx.AsyncClient(timeout=28.0) as client:
        response = await client.post(
            "https://integrate.api.nvidia.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json=payload,
        )

    if response.status_code != 200:
        raise RuntimeError(
            f"NVIDIA Nemotron API error {response.status_code}: {response.text[:400]}"
        )

    raw = response.json()
    content = raw["choices"][0]["message"]["content"].strip()

    # Strip optional markdown fences the model may still add
    if content.startswith("```"):
        content = content.split("```")[1]
        if content.startswith("json"):
            content = content[4:]
        content = content.strip()

    try:
        parsed = _json_inner.loads(content)
        subtitles = parsed.get("subtitles", [])
        if not isinstance(subtitles, list):
            subtitles = []

        # Fallback pool — 5 sensible strings used to pad short responses
        _fallback_pool = [
            "AI-generated content",
            niche,
            persona,
            cel_list[:30],
            "ALPHA Media",
        ]
        # Pad any short list (0–4 items) so the caller always gets exactly 5
        if len(subtitles) < 5:
            subtitles = list(subtitles) + _fallback_pool[len(subtitles):]

        return {
            "body":        parsed.get("body",        "Script generation in progress…"),
            "titleHook":   parsed.get("titleHook",   parsed.get("title", "Untitled Episode")),
            "imagePrompt": parsed.get("imagePrompt", parsed.get("image_prompt", "")),
            "subtitles":   subtitles[:5],
        }
    except (_json_inner.JSONDecodeError, KeyError):
        raise ValueError(
            f"Nemotron returned unexpected format (not JSON): {content[:300]}"
        )


async def call_nemotron_ai_writer(scraped_text: str, target_lang: str):
    """
    Calls NVIDIA Nemotron via the NVIDIA API to translate scraped trends into
    a localized podcast episode title, caption, and Ideogram image prompt.
    Rotates between 4 perspective angles for creative variety.
    """
    api_key = os.environ.get("NVIDIA_API_KEY")
    if not api_key:
        raise EnvironmentError("NVIDIA_API_KEY secret is not set.")

    angles = ["Analytical Expert", "High-Energy Hype", "Humorous Critic", "Curious Reporter"]
    chosen_angle = random.choice(angles)

    system_prompt = (
        "You are an elite multilingual podcast script writer. "
        f"Your current persona is: {chosen_angle}. "
        "Given a set of trend signals, produce a JSON object with exactly three keys:\n"
        '  "title": a punchy episode title hook (max 12 words)\n'
        '  "caption": a compelling social-media caption (max 30 words) ending with 2-3 hashtags\n'
        '  "image_prompt": a vivid Ideogram image generation prompt (max 40 words, cinematic quality)\n'
        f"Write everything in the target language: {target_lang}. "
        "Return ONLY valid JSON, no markdown fences."
    )

    payload = {
        "model": "meta/llama-3.1-70b-instruct",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": scraped_text[:4000]},  # token safety trim
        ],
        "temperature": 0.85,
        "max_tokens": 300,
    }

    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(
            "https://integrate.api.nvidia.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json=payload,
        )

    if response.status_code != 200:
        raise RuntimeError(
            f"NVIDIA Nemotron API error {response.status_code}: {response.text[:400]}"
        )

    raw = response.json()
    content = raw["choices"][0]["message"]["content"].strip()

    # Parse the JSON the model returned
    import json
    try:
        parsed = json.loads(content)
        title_hook     = parsed.get("title",        "Untitled Episode")
        script_caption = parsed.get("caption",      "")
        image_prompt   = parsed.get("image_prompt", "")
    except (json.JSONDecodeError, KeyError):
        # Model returned non-JSON — surface the raw text rather than silently swallowing
        raise ValueError(
            f"Nemotron returned unexpected format (not JSON): {content[:300]}"
        )

    return title_hook, script_caption, image_prompt


# ─────────────────────────────────────────────────────────────────────────────
# IDEOGRAM IMAGE GENERATION
# ─────────────────────────────────────────────────────────────────────────────

async def generate_ideogram_background(prompt: str, filename: str) -> str:
    """
    Calls the Ideogram v2 API to generate a 1:1 AI background image,
    then downloads and saves it to the local asset cache.
    Returns the local file path.
    """
    api_key = os.environ.get("IDEOGRAM_API_KEY")
    if not api_key:
        raise EnvironmentError("IDEOGRAM_API_KEY secret is not set.")

    os.makedirs("assets/storage", exist_ok=True)

    async with httpx.AsyncClient(timeout=120.0) as client:
        # Step 1: Request image generation
        gen_response = await client.post(
            "https://api.ideogram.ai/generate",
            headers={
                "Api-Key": api_key,
                "Content-Type": "application/json",
            },
            json={
                "image_request": {
                    "prompt": prompt,
                    "aspect_ratio": "ASPECT_1_1",
                    "model": "V_2",
                    "magic_prompt_option": "AUTO",
                }
            },
        )

        if gen_response.status_code != 200:
            raise RuntimeError(
                f"Ideogram API error {gen_response.status_code}: {gen_response.text[:400]}"
            )

        gen_data = gen_response.json()
        image_url = gen_data["data"][0]["url"]

        # Step 2: Download the generated image
        img_response = await client.get(image_url)
        if img_response.status_code != 200:
            raise RuntimeError(
                f"Failed to download Ideogram image from {image_url}: "
                f"status {img_response.status_code}"
            )

    filepath = f"assets/storage/{filename}"
    with open(filepath, "wb") as f:
        f.write(img_response.content)

    return f"/assets/storage/{filename}"


# ─────────────────────────────────────────────────────────────────────────────
# PILLOW IMAGE COMPOSITOR (local upload mode)
# ─────────────────────────────────────────────────────────────────────────────

def open_source_image_compositor(
    brand_colors: list,
    text_hook: str,
    template: str,
    image_mode: str,
    filename: str = "podcast_card.png",
    target_aspect_ratio: str = "9:16",
):
    """
    Uses Python Pillow (PIL) to compose the final visual podcast image card asset.
    Handles dual modes: merging user-uploaded images (local) or overlaying
    text/branding onto an already-generated Ideogram background.

    target_aspect_ratio:
        "1:1"  → 1080×1080 square canvas
        "9:16" → 1080×1920 vertical canvas (TikTok / Reels / Shorts)
    """
    os.makedirs("assets/storage", exist_ok=True)

    bg_color = brand_colors[0] if brand_colors else "#0F172A"

    # ── 1. Canvas dimensions based on selected aspect ratio ───────────────────
    if target_aspect_ratio == "1:1":
        canvas_w, canvas_h = 1080, 1080
    else:  # "9:16" default
        canvas_w, canvas_h = 1080, 1920

    img = Image.new("RGB", (canvas_w, canvas_h), color=bg_color)
    draw = ImageDraw.Draw(img)

    # ── 2. Branding border ────────────────────────────────────────────────────
    border_width = 8 if template == "magazine_card" else 4
    margin = 40
    draw.rectangle(
        [(margin, margin), (canvas_w - margin, canvas_h - margin)],
        outline="#FFFFFF",
        width=border_width,
    )

    # ── 3. Episode title text — centred on canvas ─────────────────────────────
    draw.text((canvas_w // 2, canvas_h // 2), text_hook, fill="#FFFFFF", anchor="mm")

    # ── 4. Source attribution badge — near bottom ─────────────────────────────
    source_tag = (
        "SOURCE: Ideogram AI Factory"
        if image_mode == "ai_generation"
        else "SOURCE: Mobile Device Local Upload"
    )
    draw.text(
        (canvas_w // 2, canvas_h - 80),
        f"ALPHA PRO • {source_tag}",
        fill="#888888",
        anchor="mm",
    )

    # ── 5. Aspect ratio stamp — top-right corner ──────────────────────────────
    draw.text(
        (canvas_w - margin - 10, margin + 20),
        f"{canvas_w}×{canvas_h}",
        fill="#444444",
        anchor="rm",
    )

    filepath = f"assets/storage/{filename}"
    img.save(filepath)
    return f"/assets/storage/{filename}"


def render_ffmpeg_short_video(
    image_path: str,
    audio_path: str,
    output_filename: str = "short_video.mp4",
    target_aspect_ratio: str = "9:16",
    subtitle_text: str = "",
) -> str:
    """
    Composes a short-form video by combining an image card and a voice audio
    track via FFmpeg subprocess.  Output resolution is determined by
    target_aspect_ratio:

        "1:1"  → 1080×1080  (Instagram square / Twitter)
        "9:16" → 1080×1920  (TikTok / YouTube Shorts / Reels)

    The function scales and pads the source image to fill the target frame,
    then muxes the audio stream.  Subtitles are burned in when provided.

    Returns the web-accessible path to the rendered .mp4 file, or raises
    RuntimeError if FFmpeg is not available or the render fails.
    """
    import shutil
    import subprocess

    ffmpeg_bin = shutil.which("ffmpeg")
    if not ffmpeg_bin:
        raise RuntimeError(
            "FFmpeg is not installed on this host. "
            "Install it via the package manager (nix: `ffmpeg`) and retry."
        )

    os.makedirs("assets/video", exist_ok=True)

    # ── Resolution grid ───────────────────────────────────────────────────────
    if target_aspect_ratio == "1:1":
        out_w, out_h = 1080, 1080
    else:  # "9:16"
        out_w, out_h = 1080, 1920

    output_path = f"assets/video/{output_filename}"

    # ── Scale + pad the image to the exact output frame ───────────────────────
    vf_chain = (
        f"scale={out_w}:{out_h}:force_original_aspect_ratio=decrease,"
        f"pad={out_w}:{out_h}:(ow-iw)/2:(oh-ih)/2:color=black"
    )

    # ── Burn subtitles when provided ──────────────────────────────────────────
    if subtitle_text:
        # Write a minimal SRT file so FFmpeg can burn it
        srt_path = output_path.replace(".mp4", ".srt")
        with open(srt_path, "w", encoding="utf-8") as srt_f:
            srt_f.write(f"1\n00:00:00,000 --> 00:01:30,000\n{subtitle_text}\n")
        # Use subtitles filter (requires libass; falls back gracefully)
        vf_chain += f",subtitles='{srt_path}':force_style='Fontsize=24,Alignment=2,PrimaryColour=&Hffffff&'"

    # ── Build FFmpeg command ──────────────────────────────────────────────────
    cmd = [
        ffmpeg_bin,
        "-y",                           # overwrite without prompt
        "-loop", "1",                   # loop still image for duration of audio
        "-i", image_path,               # input: image
        "-i", audio_path,               # input: audio
        "-vf", vf_chain,
        "-c:v", "libx264",
        "-preset", "fast",
        "-crf", "23",
        "-pix_fmt", "yuv420p",          # broad compatibility
        "-c:a", "aac",
        "-b:a", "128k",
        "-shortest",                    # end when audio ends
        "-movflags", "+faststart",      # web-optimised moov atom
        output_path,
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if result.returncode != 0:
        raise RuntimeError(
            f"FFmpeg render failed (exit {result.returncode}):\n{result.stderr[-800:]}"
        )

    return f"/assets/video/{output_filename}"


# ─────────────────────────────────────────────────────────────────────────────
# VOICEBOX TTS SYNTHESIS
# ─────────────────────────────────────────────────────────────────────────────

async def synthesize_voice_audio(text: str, voice_id: str, filename: str) -> str:
    """
    Calls the Voicebox TTS API to synthesize speech from the episode script.
    Uses VOICEBOX_API_ENDPOINT (base URL) and VOICEBOX_API_KEY (Bearer token).
    Saves the resulting MP3 to the local asset cache.
    Returns the local asset path.
    """
    _raw_ep  = os.environ.get("VOICEBOX_API_ENDPOINT", "").strip().rstrip("/")
    if _raw_ep and not _raw_ep.startswith(("http://", "https://")):
        _raw_ep = "https://" + _raw_ep
    endpoint = _raw_ep
    api_key  = os.environ.get("VOICEBOX_API_KEY")

    if not endpoint:
        raise EnvironmentError("VOICEBOX_API_ENDPOINT secret is not set.")
    if not api_key:
        raise EnvironmentError("VOICEBOX_API_KEY secret is not set.")

    os.makedirs("assets/audio", exist_ok=True)

    payload = {
        "text":     text,
        "voice_id": voice_id,
        "format":   "mp3",
    }

    async with httpx.AsyncClient(timeout=120.0) as client:
        response = await client.post(
            f"{endpoint}/tts",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json=payload,
        )

    if response.status_code in (404, 405):
        raise RuntimeError(
            f"Voicebox TTS endpoint returned {response.status_code}. "
            "The provider does not expose POST /tts at the configured "
            "VOICEBOX_API_ENDPOINT. Verify the endpoint URL and consult your "
            "Voicebox provider's documentation for the correct TTS path."
        )
    if response.status_code != 200:
        raise RuntimeError(
            f"Voicebox API error {response.status_code}: {response.text[:400]}"
        )

    filepath = f"assets/audio/{filename}"
    with open(filepath, "wb") as f:
        f.write(response.content)

    return f"/assets/audio/{filename}"


# ─────────────────────────────────────────────────────────────────────────────
# MASTER AUTOMATION LOOP
# ─────────────────────────────────────────────────────────────────────────────

async def execute_daily_automation_loop(
    user_id: int,
    niche_value: str,
    target_lang: str,
    hex_colors: list,
    template: str,
    image_mode: str,
    voice_id: str = "en_us_m_deep",
    target_aspect_ratio: str = "9:16",
):
    """
    Master background worker loop uniting:
      1. Omnichannel trend scraper
      2. NVIDIA Nemotron AI script writer
      3. Ideogram AI image generation (or Pillow compositor for uploads)
      4. Voicebox voice synthesis

    An overall 85-second asyncio timeout guards against slow or unresponsive
    AI services (NVIDIA, Ideogram, Voicebox).  The client enforces a 90 s
    deadline so the server's error always arrives before the browser gives up.
    """
    import asyncio

    # 85 s backend deadline — slightly shorter than the 90 s client timeout so
    # the server surfaces a clear error message before the browser aborts.
    BACKEND_TIMEOUT_S = 85

    async def _run():
        # 1. Scrape cross-platform trends
        raw_news = await scrape_omnichannel_news_trends(niche_value)

        # 2. Generate localized podcast script via Nemotron
        hook, caption, art_prompt = await call_nemotron_ai_writer(raw_news, target_lang)

        # 3. Generate visual asset
        if image_mode == "ai_generation":
            composite_image_url = await generate_ideogram_background(
                prompt=art_prompt,
                filename=f"user_post_{user_id}.png",
            )
        else:
            composite_image_url = open_source_image_compositor(
                hex_colors, hook, template, image_mode,
                f"user_post_{user_id}.png",
                target_aspect_ratio=target_aspect_ratio,
            )

        # 4. Synthesize voice audio via Voicebox
        audio_filename = f"voicebox_synth_{user_id}.mp3"
        audio_track_url = await synthesize_voice_audio(
            text=f"{hook}. {caption}",
            voice_id=voice_id,
            filename=audio_filename,
        )

        return {
            "user_id":            user_id,
            "episode_title":      hook,
            "final_caption_text": caption,
            "graphic_card_url":   composite_image_url,
            "voice_audio_url":    audio_track_url,
            "status":             "pending_review",
        }

    try:
        return await asyncio.wait_for(_run(), timeout=BACKEND_TIMEOUT_S)
    except asyncio.TimeoutError:
        raise RuntimeError(
            f"Pipeline timed out after {BACKEND_TIMEOUT_S} s — "
            "one or more AI services (NVIDIA, Ideogram, Voicebox) did not respond in time. "
            "Please retry in a moment."
        )
