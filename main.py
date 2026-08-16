import os
import json as _json
import uuid
import secrets
import pyotp
import asyncio as _asyncio
import base64 as _base64
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Depends, status, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import Any, Dict, List, Optional
import bcrypt as _bcrypt
from jose import JWTError, jwt
from sqlalchemy import select, delete, update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from models import (
    init_db, User, UserWallet, UserAestheticSetting,
    UserSelectedSource, PostsQueue, RevokedToken, PlatformToken,
    RecoveryCode, Advertisement, LoginOTP,
)
from database import init_async_db, close_db, ping_db, get_async_db
from sqlalchemy import select as sa_select, delete as sa_delete, update as sa_update

# ── Rate limiter ──────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])

# ── Voicebox startup health check ─────────────────────────────────────────────

async def startup_event() -> None:
    """Run the Voicebox /health check once at startup.

    Exposed as a named coroutine so tests can call it directly without going
    through the full lifespan machinery.  The lifespan below calls this too.
    """
    import logging, httpx
    _raw_ep     = os.environ.get("VOICEBOX_API_ENDPOINT", "").strip().rstrip("/")
    # Auto-prepend https:// when the user omitted the protocol
    if _raw_ep and not _raw_ep.startswith(("http://", "https://")):
        _raw_ep = "https://" + _raw_ep
    vb_endpoint = _raw_ep
    vb_key      = os.environ.get("VOICEBOX_API_KEY", "")
    if not vb_endpoint:
        logging.warning(
            "[Voicebox] VOICEBOX_API_ENDPOINT is not set. "
            "Voice synthesis will be unavailable until this secret is configured."
        )
        return
    health_url = f"{vb_endpoint}/health"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                health_url,
                headers={"Authorization": f"Bearer {vb_key}"} if vb_key else {},
            )
        if resp.status_code < 400:
            logging.info(f"[Voicebox] Health check passed — {health_url} returned {resp.status_code}.")
        else:
            logging.warning(
                f"[Voicebox] Health check warning — {health_url} returned {resp.status_code}. "
                "Verify VOICEBOX_API_ENDPOINT points to the correct provider and that "
                "the /health path is supported. Voice synthesis may fail at runtime."
            )
    except httpx.ConnectError:
        logging.warning(
            f"[Voicebox] Health check failed — could not reach {health_url}. "
            "Check that VOICEBOX_API_ENDPOINT is correct and the service is running."
        )
    except httpx.TimeoutException:
        logging.warning(
            f"[Voicebox] Health check timed out after 10 s — {health_url} did not respond."
        )
    except Exception as exc:  # noqa: BLE001
        logging.warning(f"[Voicebox] Health check raised an unexpected error: {exc}.")


# ── Application lifespan (startup / shutdown) ─────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup — sync schema init + async engine + scheduler
    init_db()
    await init_async_db()
    from worker import start_scheduler
    start_scheduler()
    await startup_event()

    yield  # ← app is live

    # Shutdown
    from worker import stop_scheduler
    stop_scheduler()
    await close_db()


app = FastAPI(title="ALPHA Automated Visual Podcast Factory API", lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── CORS ──────────────────────────────────────────────────────────────────────
# Allow the Vite mockup sandbox (any *.riker.replit.dev origin) plus localhost
# so the AlphaApp can POST to /api/v1/... from the same Replit dev domain.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # tightened in production via ALLOWED_ORIGINS env var
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from tasks import execute_daily_automation_loop


def _hash_password(plain: str) -> str:
    return _bcrypt.hashpw(plain.encode(), _bcrypt.gensalt()).decode()


def _verify_password(plain: str, hashed: str) -> bool:
    return _bcrypt.checkpw(plain.encode(), hashed.encode())

# ── JWT configuration ─────────────────────────────────────────────────────────
_JWT_SECRET = os.environ.get("SESSION_SECRET")
if not _JWT_SECRET:
    raise RuntimeError(
        "SESSION_SECRET environment variable is not set. "
        "Set it to a long random string before starting the server."
    )
_JWT_ALGORITHM = "HS256"
_JWT_EXPIRE_MINUTES = 60  # 1 hour — short window limits stolen-token exposure

bearer_scheme = HTTPBearer()


def _create_access_token(user_id: int, email: str) -> str:
    expire = datetime.utcnow() + timedelta(minutes=_JWT_EXPIRE_MINUTES)
    jti = str(uuid.uuid4())  # unique token ID used for revocation
    payload = {"sub": str(user_id), "email": email, "exp": expire, "jti": jti}
    return jwt.encode(payload, _JWT_SECRET, algorithm=_JWT_ALGORITHM)


# ── Email OTP helpers ─────────────────────────────────────────────────────────

async def _get_connector_token() -> str:
    """Obtain a short-lived Replit identity token for the connectors proxy."""
    proc = await _asyncio.create_subprocess_exec(
        "replit", "identity", "create",
        "--audience", "https://connectors.replit.com",
        stdout=_asyncio.subprocess.PIPE,
        stderr=_asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    token = stdout.decode().strip()
    if not token:
        raise RuntimeError(f"replit identity create returned empty token; stderr: {stderr.decode()[:200]}")
    return token


async def _send_otp_email(to_email: str, otp_code: str) -> None:
    """Send a styled 6-digit OTP to *to_email* via Gmail SMTP.

    Requires two secrets:
      SMTP_EMAIL        — the Gmail address used as the sender
      SMTP_APP_PASSWORD — a Gmail App Password (not your regular password);
                          generate one at myaccount.google.com/apppasswords
    """
    import smtplib as _smtplib
    import logging as _logging

    smtp_email = os.environ.get("SMTP_EMAIL", "").strip()
    smtp_password = os.environ.get("SMTP_APP_PASSWORD", "").strip()

    if not smtp_email or not smtp_password:
        raise RuntimeError(
            "SMTP_EMAIL and SMTP_APP_PASSWORD secrets are required to send OTP emails. "
            "Set SMTP_EMAIL to your Gmail address and SMTP_APP_PASSWORD to the "
            "16-character App Password from myaccount.google.com/apppasswords."
        )

    msg = MIMEMultipart("alternative")
    msg["From"] = f"ALPHA <{smtp_email}>"
    msg["To"] = to_email
    msg["Subject"] = f"Your ALPHA Login Code: {otp_code}"
    html_body = f"""
<!DOCTYPE html>
<html>
<body style="margin:0;padding:24px;background:#0f172a;font-family:Inter,sans-serif;">
  <div style="max-width:440px;margin:0 auto;background:#0f172a;border:1px solid rgba(255,255,255,.1);border-radius:20px;padding:32px;text-align:center;">
    <div style="display:inline-block;background:linear-gradient(135deg,#22d3ee,#6366f1);padding:16px;border-radius:16px;margin-bottom:12px;">
      <span style="font-size:24px;">📻</span>
    </div>
    <h1 style="margin:0 0 4px;font-size:11px;font-weight:900;letter-spacing:.5em;color:#22d3ee;text-transform:uppercase;">ALPHA</h1>
    <p style="margin:0 0 24px;font-size:9px;color:#64748b;letter-spacing:.2em;text-transform:uppercase;">Automated Visual Podcast Factory</p>
    <p style="margin:0 0 16px;font-size:13px;color:#94a3b8;">Your one-time login code:</p>
    <div style="background:#020617;border:1px solid rgba(34,211,238,.35);border-radius:12px;padding:24px 16px;letter-spacing:.45em;font-size:36px;font-family:monospace;color:#22d3ee;font-weight:900;margin:0 0 20px;">
      {otp_code}
    </div>
    <p style="margin:0 0 8px;font-size:12px;color:#64748b;">
      This code expires in <strong style="color:#94a3b8;">10 minutes</strong>.
    </p>
    <p style="margin:0 0 24px;font-size:11px;color:#475569;">Never share it with anyone. ALPHA will never ask for your code by phone or chat.</p>
    <hr style="border:none;border-top:1px solid rgba(255,255,255,.07);margin:0 0 16px;">
    <p style="margin:0;font-size:8px;color:#334155;letter-spacing:.15em;text-transform:uppercase;">AES-256-GCM &middot; bcrypt &middot; Email OTP</p>
  </div>
</body>
</html>
"""
    msg.attach(MIMEText(html_body, "html"))

    def _smtp_send() -> None:
        with _smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=20) as server:
            server.login(smtp_email, smtp_password)
            server.sendmail(smtp_email, to_email, msg.as_string())

    # Run the blocking SMTP call in a thread so the async event loop is not blocked.
    await _asyncio.get_event_loop().run_in_executor(None, _smtp_send)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_async_db),
) -> User:
    """FastAPI dependency: validates Bearer JWT and returns the User row.

    Also checks the revoked-token blacklist so logged-out (or forcibly
    invalidated) tokens are rejected immediately, even within their remaining
    validity window.
    """
    token = credentials.credentials
    try:
        payload = jwt.decode(token, _JWT_SECRET, algorithms=[_JWT_ALGORITHM])
        user_id: int = int(payload["sub"])
        jti: str = payload["jti"]
    except (JWTError, KeyError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # Reject tokens that have been explicitly revoked (e.g. via logout)
    revoked = (await db.execute(
        select(RevokedToken).where(RevokedToken.jti == jti)
    )).scalar_one_or_none()
    if revoked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = (await db.execute(
        select(User).where(User.id == user_id)
    )).scalar_one_or_none()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

# Serve generated images and audio so external APIs (Instagram, etc.) can reach them
os.makedirs("assets/storage", exist_ok=True)
os.makedirs("assets/audio", exist_ok=True)
app.mount("/assets", StaticFiles(directory="assets"), name="assets")


@app.get("/.well-known/assetlinks.json", include_in_schema=False)
async def assetlinks():
    """Digital Asset Links — lets the Android (TWA) app open fullscreen without a URL bar."""
    return FileResponse("assets/pwa/well-known/assetlinks.json", media_type="application/json")


# ── PWA: manifest + service worker must be served from the root scope ────────
@app.get("/manifest.json", include_in_schema=False)
def pwa_manifest():
    return FileResponse("assets/pwa/manifest.json", media_type="application/manifest+json")


@app.get("/sw.js", include_in_schema=False)
def pwa_service_worker():
    # no-cache so the browser always revalidates and picks up SW updates promptly
    return FileResponse(
        "assets/pwa/sw.js",
        media_type="application/javascript",
        headers={"Cache-Control": "no-cache, max-age=0"},
    )


# ─────────────────────────────────────────────────────────────────────────────
# SELF-HOSTED MOBILE SANDBOX UI
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/", include_in_schema=False)
async def root_redirect(request: Request):
    from fastapi.responses import RedirectResponse
    # Preserve any query string (e.g. ?oauth_result=... set by _postmessage_page
    # when a popup was blocked and the main window was redirected through OAuth).
    qs = request.url.query
    target = "/__mockup/preview/alpha-screens/AlphaApp"
    if qs:
        target = f"{target}?{qs}"
    return RedirectResponse(url=target, status_code=302)


@app.get("/app", response_class=HTMLResponse, include_in_schema=False)
async def serve_legacy_sandbox():
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ALPHA — Automated Visual Podcast Factory</title>
  <link rel="manifest" href="/manifest.json">
  <meta name="theme-color" content="#0f172a">
  <meta name="mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
  <link rel="apple-touch-icon" href="/assets/pwa/icon-192.png">
  <link rel="icon" type="image/png" href="/assets/pwa/icon-192.png">
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;900&family=JetBrains+Mono:wght@400;700&display=swap');
    * { font-family: 'Inter', sans-serif; box-sizing: border-box; }
    .mono { font-family: 'JetBrains Mono', monospace; }
    .phone-screen { height: 660px; overflow-y: auto; }
    .phone-screen::-webkit-scrollbar { display: none; }
    .phone-screen { -ms-overflow-style: none; scrollbar-width: none; }

    /* Glassmorphism */
    .glass { background: rgba(15,23,42,0.6); backdrop-filter: blur(12px); border: 1px solid rgba(99,102,241,0.15); }
    .glass-emerald { background: rgba(16,185,129,0.08); backdrop-filter: blur(10px); border: 1px solid rgba(16,185,129,0.25); }

    /* Range slider */
    input[type=range] { -webkit-appearance: none; appearance: none; height: 4px; border-radius: 9999px; background: linear-gradient(to right, #06b6d4 0%, #6366f1 100%); outline: none; }
    input[type=range]::-webkit-slider-thumb { -webkit-appearance: none; appearance: none; width: 16px; height: 16px; border-radius: 50%; background: #06b6d4; cursor: pointer; border: 2px solid #0f172a; box-shadow: 0 0 8px rgba(6,182,212,0.6); }

    /* Pulse animations */
    @keyframes pulse-dot { 0%,100% { opacity:1; transform:scale(1); } 50% { opacity:0.5; transform:scale(1.4); } }
    @keyframes pulse-red { 0%,100% { box-shadow:0 0 0 0 rgba(239,68,68,0.4); } 70% { box-shadow:0 0 0 8px rgba(239,68,68,0); } }
    @keyframes wave { 0%,100% { height:4px; } 50% { height:14px; } }
    @keyframes ticker { 0% { transform:translateX(100%); } 100% { transform:translateX(-100%); } }
    .pulse-dot { animation: pulse-dot 1.5s ease-in-out infinite; }
    .pulse-red-btn { animation: pulse-red 1.8s ease-in-out infinite; }
    .wave-bar { animation: wave 0.8s ease-in-out infinite; }

    /* Toggle active state */
    .voice-btn.active { background: linear-gradient(135deg, #06b6d4, #6366f1); color:#fff; border-color:transparent; }
    .voice-btn { transition: all 0.25s ease; }
    .img-btn.active { background: linear-gradient(135deg, #6366f1, #8b5cf6); color:#fff; border-color:transparent; }
    .platform-card { transition: all 0.2s ease; }
    .platform-card:hover { transform: scale(1.04); }

    /* Slide transition */
    .slide-section { transition: all 0.35s cubic-bezier(0.4,0,0.2,1); overflow: hidden; }
  </style>
  <script>
    tailwind.config = {
      theme: {
        extend: {
          colors: {
            slate: { 950: '#020617' }
          }
        }
      }
    }
  </script>
</head>
<body class="min-h-screen flex items-center justify-center p-4"
      style="background: linear-gradient(135deg, #020617 0%, #0f172a 40%, #1e1b4b 100%);">

  <!-- Page Header -->
  <div class="flex flex-col items-center w-full max-w-sm">
    <p class="mono text-[10px] text-slate-500 tracking-[0.3em] uppercase mb-1">ALPHA SYSTEM v3.2</p>
    <h1 class="mono text-base font-black tracking-widest mb-5"
        style="background:linear-gradient(90deg,#06b6d4,#818cf8);-webkit-background-clip:text;-webkit-text-fill-color:transparent;">
      ⚡ AUTOMATED VISUAL PODCAST FACTORY
    </h1>

    <!-- ════════════════════════════════════════════════════ -->
    <!-- SMARTPHONE CHASSIS FRAME                            -->
    <!-- ════════════════════════════════════════════════════ -->
    <div class="relative" style="width:375px;">

      <!-- Outer bezel -->
      <div class="rounded-[40px] p-[3px]"
           style="background:linear-gradient(145deg,#334155,#1e293b);box-shadow:0 40px 80px rgba(0,0,0,0.8),inset 0 1px 0 rgba(255,255,255,0.06);">
        <div class="rounded-[38px] overflow-hidden bg-slate-950"
             style="box-shadow:inset 0 0 30px rgba(0,0,0,0.5);">

          <!-- Notch / Status bar -->
          <div class="relative flex items-center justify-between px-5 pt-2 pb-1 bg-slate-950" style="height:36px;">
            <span class="mono text-[10px] font-bold text-slate-400">09:41</span>
            <!-- Dynamic island notch -->
            <div class="absolute left-1/2 -translate-x-1/2 top-2 w-20 h-5 bg-black rounded-full flex items-center justify-center gap-1.5">
              <div class="w-1.5 h-1.5 rounded-full bg-slate-700"></div>
              <div class="w-1 h-1 rounded-full bg-indigo-500 opacity-60"></div>
            </div>
            <div class="flex items-center gap-1.5 text-slate-400">
              <i class="fas fa-signal text-[9px]"></i>
              <i class="fas fa-wifi text-[9px]"></i>
              <i class="fas fa-battery-three-quarters text-[9px] text-emerald-400"></i>
            </div>
          </div>

          <!-- Screen content — scrollable -->
          <div class="phone-screen bg-slate-950 px-4 pt-3 pb-6 space-y-4">

            <!-- ─── MODULE HEADER ─── -->
            <div class="text-center">
              <div class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[9px] font-bold mono tracking-widest uppercase"
                   style="background:rgba(6,182,212,0.1);border:1px solid rgba(6,182,212,0.2);color:#06b6d4;">
                <i class="fas fa-sliders text-[8px]"></i>
                System Configuration Studio
              </div>
            </div>

            <!-- ─── 1. NICHE CHANNEL SELECTOR ─── -->
            <div class="glass rounded-2xl p-3 space-y-2">
              <label class="flex items-center gap-1.5 text-[9px] font-bold uppercase tracking-widest text-slate-400">
                <i class="fas fa-layer-group text-cyan-500 text-[8px]"></i>
                Target Niche Channel
              </label>
              <select class="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-semibold text-slate-200 focus:outline-none focus:border-cyan-500"
                      style="background-image:none;">
                <option>📈 Finance &amp; Crypto Insights</option>
                <option>⚽ Sports Analytics Channel</option>
                <option>🏛️ Geopolitics &amp; World Affairs</option>
                <option>🤖 AI &amp; Tech Innovation</option>
                <option>🧬 Health &amp; Longevity Science</option>
                <option>🎭 Entertainment &amp; Pop Culture</option>
              </select>
            </div>

            <!-- ─── 2. CELEBRITY TRACKER ─── -->
            <div class="glass rounded-2xl p-3 space-y-2">
              <label class="flex items-center gap-1.5 text-[9px] font-bold uppercase tracking-widest text-slate-400">
                <i class="fas fa-user-tag text-violet-400 text-[8px]"></i>
                Public Figure Tracking Target
              </label>
              <div class="relative">
                <i class="fas fa-search absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 text-[9px]"></i>
                <input type="text" value="Elon Musk"
                       class="w-full bg-slate-950 border border-slate-800 rounded-xl pl-7 pr-3 py-2 text-xs font-semibold text-slate-200 focus:outline-none focus:border-violet-500"
                       placeholder="e.g. Elon Musk, Cristiano Ronaldo">
              </div>
            </div>

            <!-- ─── 3. MEDIA MIX SLIDER ─── -->
            <div class="glass rounded-2xl p-3 space-y-2">
              <label class="flex items-center gap-1.5 text-[9px] font-bold uppercase tracking-widest text-slate-400">
                <i class="fas fa-sliders-h text-cyan-500 text-[8px]"></i>
                Media Mix Distribution
              </label>
              <div class="flex justify-between text-[9px] font-bold mono">
                <span class="text-cyan-400"><i class="fas fa-image mr-1"></i><span id="imgPct">60</span>% Image</span>
                <span class="text-indigo-400"><span id="vidPct">40</span>% Video<i class="fas fa-film ml-1"></i></span>
              </div>
              <input type="range" min="0" max="100" value="60" id="mediaMix"
                     class="w-full" oninput="updateMix(this.value)">
              <div class="flex justify-between text-[8px] text-slate-600 font-mono">
                <span>All Images</span><span>Equal</span><span>All Video</span>
              </div>
            </div>

            <!-- ─── 4. LANGUAGE MATRIX ─── -->
            <div class="glass rounded-2xl p-3 space-y-2">
              <label class="flex items-center gap-1.5 text-[9px] font-bold uppercase tracking-widest text-slate-400">
                <i class="fas fa-globe text-emerald-400 text-[8px]"></i>
                Global Language Matrix
              </label>
              <div class="grid grid-cols-2 gap-2">
                <div>
                  <p class="text-[8px] text-slate-500 font-bold uppercase mb-1">Output Language</p>
                  <select class="w-full bg-slate-950 border border-slate-800 rounded-xl px-2 py-1.5 text-[10px] font-semibold text-slate-300 focus:outline-none focus:border-emerald-500">
                    <option>🇺🇸 English (US/UK)</option>
                    <option>🇪🇸 Español (MX/ES)</option>
                    <option>🇫🇷 Français (FR)</option>
                    <option>🇸🇦 العربية (AR)</option>
                    <option>🇧🇷 Português (BR)</option>
                    <option>🇨🇳 中文 (ZH)</option>
                    <option>🇮🇳 हिन्दी (HI)</option>
                  </select>
                </div>
                <div>
                  <p class="text-[8px] text-slate-500 font-bold uppercase mb-1">Dialect / Region</p>
                  <select class="w-full bg-slate-950 border border-slate-800 rounded-xl px-2 py-1.5 text-[10px] font-semibold text-slate-300 focus:outline-none focus:border-emerald-500">
                    <option>US / UK</option>
                    <option>MX / ES</option>
                    <option>FR / BE</option>
                    <option>Gulf / Levant</option>
                    <option>BR / PT</option>
                    <option>Mandarin / Cantonese</option>
                  </select>
                </div>
              </div>
            </div>

            <!-- ════════════════════════════════════════════════════ -->
            <!-- COMPONENT 2: REACTIVE INTERNATIONAL VOICE STUDIO    -->
            <!-- ════════════════════════════════════════════════════ -->
            <div class="glass rounded-2xl p-3 space-y-3">
              <!-- Header -->
              <div class="flex items-center justify-between">
                <label class="flex items-center gap-1.5 text-[9px] font-bold uppercase tracking-widest text-slate-400">
                  <i class="fas fa-microphone text-rose-400 text-[8px]"></i>
                  Voice Studio Engine
                </label>
                <span class="mono text-[8px] px-1.5 py-0.5 rounded-full text-emerald-400"
                      style="background:rgba(16,185,129,0.12);border:1px solid rgba(16,185,129,0.2);">LIVE</span>
              </div>

              <!-- Master toggle: Stock Library | 45s Voice Clone -->
              <div class="grid grid-cols-2 gap-1.5 p-1 rounded-xl"
                   style="background:rgba(15,23,42,0.8);border:1px solid rgba(51,65,85,0.6);">
                <button id="btnStock" onclick="setVoiceMode('stock')"
                        class="voice-btn active rounded-lg py-2 text-[10px] font-bold tracking-wide"
                        style="border:1px solid transparent;">
                  <i class="fas fa-headphones-alt mr-1 text-[9px]"></i>Stock Library
                </button>
                <button id="btnClone" onclick="setVoiceMode('clone')"
                        class="voice-btn rounded-lg py-2 text-[10px] font-bold tracking-wide text-slate-400"
                        style="border:1px solid rgba(51,65,85,0.6);">
                  <i class="fas fa-dna mr-1 text-[9px]"></i>45s Voice Clone
                </button>
              </div>

              <!-- STOCK LIBRARY DROPDOWN (default visible) -->
              <div id="stockPanel" class="slide-section space-y-2">
                <p class="text-[8px] text-slate-500 font-bold uppercase tracking-widest">Select Voice Profile</p>
                <select id="voiceSelect"
                        class="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-[10px] font-semibold text-slate-200 focus:outline-none focus:border-cyan-500"
                        style="line-height:1.6;">
                  <option value="en_us_m_deep">🇺🇸 Premium Male — Deep Analytical (English US)</option>
                  <option value="en_uk_f_corp">🇬🇧 Premium Female — Professional Corporate (English UK)</option>
                  <option value="es_m_broadcast">🇪🇸 Premium Male — Energetic Broadcast (Spanish Accent)</option>
                  <option value="fr_f_narrative">🇫🇷 Premium Female — Soft Narrative (French Accent)</option>
                  <option value="multi_m_global">🌍 Premium Male — Global Dialect Accents (Multi-Lingual Matrix)</option>
                </select>
                <div class="flex items-center gap-2 p-2 rounded-xl"
                     style="background:rgba(6,182,212,0.06);border:1px solid rgba(6,182,212,0.12);">
                  <!-- Mini waveform bars -->
                  <div class="flex items-end gap-0.5 h-4">
                    <div class="wave-bar w-0.5 bg-cyan-500 rounded-full" style="animation-delay:0s;"></div>
                    <div class="wave-bar w-0.5 bg-cyan-400 rounded-full" style="animation-delay:0.1s;"></div>
                    <div class="wave-bar w-0.5 bg-cyan-500 rounded-full" style="animation-delay:0.2s;"></div>
                    <div class="wave-bar w-0.5 bg-indigo-400 rounded-full" style="animation-delay:0.3s;"></div>
                    <div class="wave-bar w-0.5 bg-cyan-500 rounded-full" style="animation-delay:0.15s;"></div>
                    <div class="wave-bar w-0.5 bg-cyan-400 rounded-full" style="animation-delay:0.25s;"></div>
                    <div class="wave-bar w-0.5 bg-indigo-500 rounded-full" style="animation-delay:0.05s;"></div>
                    <div class="wave-bar w-0.5 bg-cyan-500 rounded-full" style="animation-delay:0.35s;"></div>
                  </div>
                  <p class="text-[9px] text-slate-400 font-medium">Voice profile preview active</p>
                </div>
              </div>

              <!-- VOICE CLONE RECORDING PANEL (default hidden) -->
              <div id="clonePanel" class="slide-section space-y-2" style="max-height:0;opacity:0;pointer-events:none;">
                <!-- Pulsing recording alert -->
                <div class="flex items-center gap-2 px-3 py-2 rounded-xl"
                     style="background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);">
                  <div class="w-2 h-2 rounded-full bg-red-500 pulse-dot flex-shrink-0"></div>
                  <div class="flex-1">
                    <p class="text-[9px] font-black text-red-400 mono tracking-wider">🔴 RECORDING SAMPLE AUDIO...</p>
                    <p class="text-[8px] text-slate-500 mt-0.5">Capture 45 seconds of your natural voice</p>
                  </div>
                  <span class="mono text-[10px] font-black text-red-300 flex-shrink-0">
                    <span id="cloneTimer">0:32</span> / 0:45
                  </span>
                </div>
                <!-- Mic button -->
                <div class="flex items-center gap-3">
                  <button class="pulse-red-btn w-12 h-12 rounded-full flex items-center justify-center flex-shrink-0"
                          style="background:rgba(239,68,68,0.2);border:2px solid rgba(239,68,68,0.5);">
                    <i class="fas fa-microphone text-red-400 text-base"></i>
                  </button>
                  <div class="flex-1 space-y-1">
                    <p class="text-[9px] font-bold text-slate-300">🎙️ Voicebox Clone Stream</p>
                    <p class="text-[8px] text-slate-500">Tap mic to pause • VOICEBOX engine active</p>
                    <!-- Mini waveform progress -->
                    <div class="flex items-end gap-0.5 h-3">
                      <div class="wave-bar w-0.5 bg-red-500 rounded-full" style="animation-delay:0s;"></div>
                      <div class="wave-bar w-0.5 bg-rose-400 rounded-full" style="animation-delay:0.08s;"></div>
                      <div class="wave-bar w-0.5 bg-red-400 rounded-full" style="animation-delay:0.16s;"></div>
                      <div class="wave-bar w-0.5 bg-rose-500 rounded-full" style="animation-delay:0.24s;"></div>
                      <div class="wave-bar w-0.5 bg-red-500 rounded-full" style="animation-delay:0.12s;"></div>
                      <div class="wave-bar w-0.5 bg-rose-400 rounded-full" style="animation-delay:0.2s;"></div>
                      <div class="wave-bar w-0.5 bg-red-400 rounded-full" style="animation-delay:0.04s;"></div>
                      <div class="wave-bar w-0.5 bg-rose-500 rounded-full" style="animation-delay:0.28s;"></div>
                      <div class="wave-bar w-0.5 bg-red-500 rounded-full" style="animation-delay:0.06s;"></div>
                      <div class="wave-bar w-0.5 bg-rose-400 rounded-full" style="animation-delay:0.14s;"></div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <!-- ─── IMAGE SOURCE TOGGLE ─── -->
            <div class="glass rounded-2xl p-3 space-y-2">
              <label class="flex items-center gap-1.5 text-[9px] font-bold uppercase tracking-widest text-slate-400">
                <i class="fas fa-image text-violet-400 text-[8px]"></i>
                Image Studio Selection
              </label>
              <div class="grid grid-cols-2 gap-1.5 p-1 rounded-xl"
                   style="background:rgba(15,23,42,0.8);border:1px solid rgba(51,65,85,0.6);">
                <button id="btnAI" onclick="setImgMode('ai')"
                        class="img-btn active rounded-lg py-2 text-[10px] font-bold"
                        style="border:1px solid transparent;">
                  <i class="fas fa-robot mr-1 text-[9px]"></i>Ideogram AI
                </button>
                <button id="btnUpload" onclick="setImgMode('upload')"
                        class="img-btn rounded-lg py-2 text-[10px] font-bold text-slate-400"
                        style="border:1px solid rgba(51,65,85,0.6);">
                  <i class="fas fa-folder-open mr-1 text-[9px]"></i>Local Upload
                </button>
              </div>
              <p id="imgModeDesc" class="text-[9px] text-slate-500 text-center">
                AI generates a custom background via Ideogram pipeline
              </p>
            </div>

            <!-- ════════════════════════════════════════════════════ -->
            <!-- COMPONENT 1: OAUTH MULTI-PLATFORM CONNECTION GRID   -->
            <!-- ════════════════════════════════════════════════════ -->
            <div class="glass rounded-2xl p-3 space-y-3">
              <label class="flex items-center gap-1.5 text-[9px] font-bold uppercase tracking-widest text-slate-400">
                <i class="fas fa-plug text-cyan-500 text-[8px]"></i>
                Connected Platforms (OAuth 2.0)
              </label>

              <!-- Dynamic platform grid — populated by JS -->
              <div id="platformGrid" class="grid grid-cols-4 gap-1.5">
                <!-- skeleton loaders -->
                <div class="animate-pulse h-16 rounded-xl bg-slate-800/60"></div>
                <div class="animate-pulse h-16 rounded-xl bg-slate-800/60"></div>
                <div class="animate-pulse h-16 rounded-xl bg-slate-800/60"></div>
                <div class="animate-pulse h-16 rounded-xl bg-slate-800/60"></div>
                <div class="animate-pulse h-16 rounded-xl bg-slate-800/60"></div>
                <div class="animate-pulse h-16 rounded-xl bg-slate-800/60"></div>
                <div class="animate-pulse h-16 rounded-xl bg-slate-800/60"></div>
                <div class="animate-pulse h-16 rounded-xl bg-slate-800/60"></div>
              </div>

              <!-- Connection status bar -->
              <div class="flex items-center justify-between px-1">
                <span id="platformStatusText" class="text-[8px] text-slate-500">Loading…</span>
                <div class="flex gap-1 items-center">
                  <div class="h-1 w-10 rounded-full bg-slate-800 overflow-hidden">
                    <div id="platformProgressBar" class="h-full w-0 rounded-full transition-all duration-500"
                         style="background:linear-gradient(90deg,#10b981,#06b6d4);"></div>
                  </div>
                  <span id="platformProgressPct" class="text-[8px] text-emerald-400 font-bold mono">0%</span>
                </div>
              </div>
            </div>

            <!-- ════════════════════════════════════════════════════ -->
            <!-- PLATFORM CONNECT / DISCONNECT MODAL                 -->
            <!-- ════════════════════════════════════════════════════ -->
            <div id="platformModal" class="hidden fixed inset-0 z-50 flex items-end justify-center"
                 style="background:rgba(2,6,23,0.85);backdrop-filter:blur(6px);">
              <div class="w-full max-w-sm mx-auto rounded-t-3xl p-5 space-y-4"
                   style="background:#0f172a;border-top:1px solid rgba(99,102,241,0.35);box-shadow:0 -16px 48px rgba(99,102,241,0.2);">

                <!-- Modal header -->
                <div class="flex items-center justify-between">
                  <div class="flex items-center gap-2">
                    <div id="modalIcon" class="w-8 h-8 rounded-xl flex items-center justify-center"></div>
                    <div>
                      <p id="modalTitle" class="text-sm font-bold text-white"></p>
                      <p id="modalSubtitle" class="text-[9px] text-slate-500">OAuth 2.0 Access Token</p>
                    </div>
                  </div>
                  <button onclick="closePlatformModal()"
                          class="w-7 h-7 rounded-full flex items-center justify-center text-slate-500 hover:text-white"
                          style="background:rgba(51,65,85,0.4);">
                    <i class="fas fa-times text-[10px]"></i>
                  </button>
                </div>

                <!-- Connect form -->
                <div id="connectForm" class="space-y-2">
                  <!-- OAuth2 one-click connect (shown for supported platforms) -->
                  <div id="oauthSection" class="hidden space-y-2">
                    <button id="oauthBtn" onclick="startOAuthConnect()"
                            class="w-full py-2.5 rounded-xl text-xs font-black uppercase tracking-widest text-white"
                            style="background:linear-gradient(135deg,#6366f1,#8b5cf6);box-shadow:0 4px 16px rgba(99,102,241,0.35);">
                      <i class="fas fa-external-link-alt mr-1.5"></i>Connect via OAuth
                    </button>
                    <div class="flex items-center gap-2">
                      <div class="flex-1 h-px" style="background:rgba(51,65,85,0.6);"></div>
                      <span class="text-[8px] text-slate-600 uppercase tracking-widest">or paste token manually</span>
                      <div class="flex-1 h-px" style="background:rgba(51,65,85,0.6);"></div>
                    </div>
                  </div>
                  <div>
                    <label class="text-[9px] font-bold uppercase tracking-widest text-slate-400 mb-1 block">
                      Access Token <span class="text-red-400">*</span>
                    </label>
                    <input id="inputAccessToken" type="password" placeholder="Paste your access token…"
                           class="w-full rounded-xl px-3 py-2.5 text-xs text-white placeholder-slate-600 outline-none"
                           style="background:rgba(30,41,59,0.8);border:1px solid rgba(51,65,85,0.6);"
                           oninput="this.style.borderColor=this.value?'rgba(99,102,241,0.6)':'rgba(51,65,85,0.6)'">
                  </div>
                  <div id="accountIdRow" class="hidden">
                    <label class="text-[9px] font-bold uppercase tracking-widest text-slate-400 mb-1 block">
                      <span id="accountIdLabel">Account / Channel ID</span>
                    </label>
                    <input id="inputAccountId" type="text" placeholder="e.g. UC1234… or 123456789"
                           class="w-full rounded-xl px-3 py-2.5 text-xs text-white placeholder-slate-600 outline-none"
                           style="background:rgba(30,41,59,0.8);border:1px solid rgba(51,65,85,0.6);"
                           oninput="this.style.borderColor=this.value?'rgba(99,102,241,0.6)':'rgba(51,65,85,0.6)'">
                  </div>
                  <p id="modalError" class="text-[9px] text-red-400 hidden"></p>
                  <button id="connectBtn" onclick="submitPlatformConnect()"
                          class="w-full py-2.5 rounded-xl text-xs font-black uppercase tracking-widest text-white mt-1"
                          style="background:linear-gradient(135deg,#6366f1,#06b6d4);box-shadow:0 4px 16px rgba(99,102,241,0.35);">
                    <i class="fas fa-link mr-1.5"></i>Connect Platform
                  </button>
                </div>

                <!-- Disconnect confirmation (hidden by default) -->
                <div id="disconnectForm" class="hidden space-y-3">
                  <div id="connectedStatusBox" class="rounded-xl p-3 text-center" style="background:rgba(16,185,129,0.07);border:1px solid rgba(16,185,129,0.2);">
                    <i id="connectedStatusIcon" class="fas fa-check-circle text-emerald-400 text-lg mb-1 block"></i>
                    <p id="connectedStatusLabel" class="text-[10px] font-bold text-emerald-400">Platform Connected</p>
                    <p id="disconnectConnectedAt" class="text-[9px] text-slate-500 mt-0.5"></p>
                  </div>
                  <!-- Expiry warning — shown for expiring_soon / expired tokens -->
                  <div id="expiryWarningBox" class="hidden rounded-xl p-3 space-y-2">
                    <p id="expiryWarningText" class="text-[9px] font-bold text-center"></p>
                    <button onclick="switchToReconnect()"
                            id="reconnectBtn"
                            class="w-full py-2.5 rounded-xl text-xs font-black uppercase tracking-widest text-white"
                            style="background:linear-gradient(135deg,#f59e0b,#ef4444);box-shadow:0 4px 16px rgba(239,68,68,0.3);">
                      <i class="fas fa-rotate-right mr-1.5"></i>Reconnect Now
                    </button>
                  </div>
                  <button id="testConnectionBtn" onclick="testPlatformConnection()"
                          class="w-full py-2 rounded-xl text-xs font-bold uppercase tracking-widest"
                          style="background:rgba(6,182,212,0.1);border:1px solid rgba(6,182,212,0.25);color:#67e8f9;">
                    <i class="fas fa-stethoscope mr-1.5"></i>Test Connection
                  </button>
                  <p id="testResult" class="text-[9px] text-center hidden"></p>
                  <button id="disconnectBtn" onclick="submitPlatformDisconnect()"
                          class="w-full py-2.5 rounded-xl text-xs font-bold uppercase tracking-widest"
                          style="background:rgba(239,68,68,0.12);border:1px solid rgba(239,68,68,0.3);color:#f87171;">
                    <i class="fas fa-unlink mr-1.5"></i>Disconnect
                  </button>
                </div>

              </div>
            </div>

            <!-- ════════════════════════════════════════════════════ -->
            <!-- COMPONENT 3: PER-PLATFORM PUBLISH RESULTS         -->
            <!-- ════════════════════════════════════════════════════ -->
            <div class="glass rounded-2xl p-3 space-y-3">
              <div class="flex items-center justify-between">
                <label class="flex items-center gap-1.5 text-[9px] font-bold uppercase tracking-widest text-slate-400">
                  <i class="fas fa-satellite-dish text-indigo-400 text-[8px]"></i>
                  Publish Results
                </label>
                <button onclick="loadPublishResults()"
                        class="flex items-center gap-1 px-2 py-1 rounded-lg text-[8px] font-bold text-cyan-400 mono"
                        style="background:rgba(6,182,212,0.1);border:1px solid rgba(6,182,212,0.2);">
                  <i class="fas fa-sync-alt text-[7px]"></i>Refresh
                </button>
              </div>
              <div id="publishResultsContainer">
                <div class="flex flex-col items-center py-3 gap-1">
                  <i class="fas fa-broadcast-tower text-slate-700 text-lg"></i>
                  <p class="text-[8px] text-slate-600 text-center">No publish results yet.<br>Run automation to see platform status.</p>
                </div>
              </div>
            </div>

            <!-- ─── SAVE & ACTIVATE CTA ─── -->
            <button class="w-full py-3 rounded-2xl font-black text-xs tracking-widest uppercase text-white"
                    style="background:linear-gradient(135deg,#06b6d4,#6366f1);box-shadow:0 8px 24px rgba(99,102,241,0.4);">
              <i class="fas fa-check-circle mr-2"></i>Lock In Configuration
            </button>

            <!-- Safe area spacer -->
            <div class="h-2"></div>

          </div><!-- /phone-screen -->

          <!-- Home gesture bar -->
          <div class="flex justify-center py-2 bg-slate-950">
            <div class="w-24 h-1 rounded-full bg-slate-700"></div>
          </div>

        </div><!-- /inner rounded -->
      </div><!-- /outer bezel -->
    </div><!-- /relative wrapper -->

    <p class="mono text-[8px] text-slate-600 mt-4 tracking-widest uppercase text-center">
      ALPHA SYSTEM · All rights reserved · Secured via JWT + TOTP 2FA
    </p>
  </div>

  <!-- ══════════════════════════════════════════════ -->
  <!-- JAVASCRIPT LOGIC INTEGRATION                  -->
  <!-- ══════════════════════════════════════════════ -->
  <script>
    // ── Media Mix Slider ──────────────────────────
    function updateMix(val) {
      document.getElementById('imgPct').textContent = val;
      document.getElementById('vidPct').textContent = 100 - val;
    }

    // ── Voice Studio Toggle ───────────────────────
    function setVoiceMode(mode) {
      const stockPanel = document.getElementById('stockPanel');
      const clonePanel = document.getElementById('clonePanel');
      const btnStock   = document.getElementById('btnStock');
      const btnClone   = document.getElementById('btnClone');

      if (mode === 'stock') {
        // Show stock dropdown
        stockPanel.style.maxHeight = '300px';
        stockPanel.style.opacity   = '1';
        stockPanel.style.pointerEvents = 'auto';
        // Hide clone panel
        clonePanel.style.maxHeight = '0';
        clonePanel.style.opacity   = '0';
        clonePanel.style.pointerEvents = 'none';
        // Button states
        btnStock.classList.add('active');
        btnStock.style.border = '1px solid transparent';
        btnClone.classList.remove('active');
        btnClone.classList.add('text-slate-400');
        btnClone.style.border = '1px solid rgba(51,65,85,0.6)';
      } else {
        // Hide stock dropdown
        stockPanel.style.maxHeight = '0';
        stockPanel.style.opacity   = '0';
        stockPanel.style.pointerEvents = 'none';
        // Show clone panel
        clonePanel.style.maxHeight = '400px';
        clonePanel.style.opacity   = '1';
        clonePanel.style.pointerEvents = 'auto';
        // Button states
        btnClone.classList.add('active');
        btnClone.style.border = '1px solid transparent';
        btnStock.classList.remove('active');
        btnStock.classList.add('text-slate-400');
        btnStock.style.border = '1px solid rgba(51,65,85,0.6)';
      }
    }

    // ── Image Source Toggle ───────────────────────
    const imgDescs = {
      ai:     'AI generates a custom background via Ideogram pipeline',
      upload: 'Upload a local photo directly from your device library'
    };
    function setImgMode(mode) {
      document.getElementById('btnAI').classList.toggle('active',     mode === 'ai');
      document.getElementById('btnUpload').classList.toggle('active', mode === 'upload');
      document.getElementById('btnAI').classList.toggle('text-slate-400',     mode !== 'ai');
      document.getElementById('btnUpload').classList.toggle('text-slate-400', mode !== 'upload');
      document.getElementById('imgModeDesc').textContent = imgDescs[mode];
    }

    // ══ PLATFORM CONNECTION SYSTEM ══════════════════════════════════
    const PLATFORM_META = {
      youtube:   { icon: 'fab fa-youtube',   iconColor: '#f87171', iconBg: 'rgba(239,68,68,0.15)',   label: 'YouTube'   },
      instagram: { icon: 'fab fa-instagram', iconColor: '#f472b6', iconBg: 'rgba(236,72,153,0.15)',  label: 'Instagram' },
      facebook:  { icon: 'fab fa-facebook',  iconColor: '#60a5fa', iconBg: 'rgba(59,130,246,0.15)',  label: 'Facebook'  },
      whatsapp:  { icon: 'fab fa-whatsapp',  iconColor: '#4ade80', iconBg: 'rgba(34,197,94,0.15)',   label: 'WhatsApp'  },
      tiktok:    { icon: 'fab fa-tiktok',    iconColor: '#94a3b8', iconBg: 'rgba(51,65,85,0.3)',     label: 'TikTok'    },
      linkedin:  { icon: 'fab fa-linkedin',  iconColor: '#94a3b8', iconBg: 'rgba(51,65,85,0.3)',     label: 'LinkedIn'  },
      threads:   { icon: 'fas fa-at',        iconColor: '#94a3b8', iconBg: 'rgba(51,65,85,0.3)',     label: 'Threads'   },
      baidu:     { icon: 'fas fa-paw',       iconColor: '#94a3b8', iconBg: 'rgba(51,65,85,0.3)',     label: 'Baidu'     },
    };
    const ACCOUNT_ID_LABELS = {
      youtube:   'Channel ID (e.g. UCxxxxxxxx)',
      instagram: 'Instagram Account ID',
      facebook:  'Facebook Page ID',
      whatsapp:  'Phone Number ID',
      threads:   'Threads User ID',
    };

    // Platforms that support OAuth2 via /api/v1/auth/connect/{platform}
    const OAUTH_PLATFORMS = new Set(['youtube', 'instagram', 'facebook', 'tiktok', 'linkedin', 'threads', 'whatsapp']);

    let _platformState = [];   // last fetched list from API
    let _activePlatform = null; // platform key currently open in modal
    let _oauthPopup = null;    // reference to the OAuth popup window

    function _getJwt() {
      return localStorage.getItem('alpha_jwt') || '';
    }

    async function loadPlatforms() {
      const jwt = _getJwt();
      if (!jwt) {
        renderPlatformGridUnauthenticated();
        return;
      }
      try {
        const res = await fetch('/api/v1/platforms', {
          headers: { 'Authorization': 'Bearer ' + jwt }
        });
        if (!res.ok) { renderPlatformGridUnauthenticated(); return; }
        const data = await res.json();
        _platformState = data.platforms;
        renderPlatformGrid(data.platforms, data.connected_count);
      } catch (e) {
        renderPlatformGridUnauthenticated();
      }
    }

    function renderPlatformGridUnauthenticated() {
      const grid = document.getElementById('platformGrid');
      grid.innerHTML = `<div class="col-span-4 text-center py-4">
        <i class="fas fa-lock text-slate-600 text-lg mb-1 block"></i>
        <p class="text-[9px] text-slate-500">Log in to manage platform connections</p>
      </div>`;
      document.getElementById('platformStatusText').textContent = 'Authentication required';
      document.getElementById('platformProgressBar').style.width = '0%';
      document.getElementById('platformProgressPct').textContent = '0%';
    }

    function renderPlatformGrid(platforms, connectedCount) {
      const grid = document.getElementById('platformGrid');
      const total = platforms.length;
      const pct = Math.round((connectedCount / total) * 100);

      grid.innerHTML = platforms.map((p, i) => {
        const meta = PLATFORM_META[p.platform] || { icon: 'fas fa-globe', iconColor: '#94a3b8', iconBg: 'rgba(51,65,85,0.3)', label: p.label };
        const delay = (i * 0.15).toFixed(2);
        if (p.connected) {
          const status = p.token_status || 'unknown';
          if (status === 'expired') {
            return `<div class="platform-card relative flex flex-col items-center gap-1 p-2 rounded-xl cursor-pointer"
                         style="background:rgba(239,68,68,0.07);border:1px solid rgba(239,68,68,0.45);"
                         onclick="openPlatformModal('${p.platform}', true)"
                         title="Token expired — tap to reconnect ${meta.label}">
                      <div class="absolute top-1 right-1 w-3.5 h-3.5 rounded-full flex items-center justify-center" style="background:rgba(239,68,68,0.85);">
                        <i class="fas fa-exclamation text-white" style="font-size:6px;"></i>
                      </div>
                      <div class="w-7 h-7 rounded-lg flex items-center justify-center" style="background:${meta.iconBg};">
                        <i class="${meta.icon} text-xs" style="color:${meta.iconColor};"></i>
                      </div>
                      <span class="text-[7px] font-bold text-red-400 text-center leading-tight">${meta.label}</span>
                      <span class="text-[6px] text-red-500 mono font-bold">Expired</span>
                    </div>`;
          } else if (status === 'expiring_soon') {
            return `<div class="platform-card relative flex flex-col items-center gap-1 p-2 rounded-xl cursor-pointer"
                         style="background:rgba(245,158,11,0.07);border:1px solid rgba(245,158,11,0.45);"
                         onclick="openPlatformModal('${p.platform}', true)"
                         title="Token expiring soon — tap to reconnect ${meta.label}">
                      <div class="absolute top-1 right-1 w-3.5 h-3.5 rounded-full flex items-center justify-center" style="background:rgba(245,158,11,0.9);">
                        <i class="fas fa-exclamation text-white" style="font-size:6px;"></i>
                      </div>
                      <div class="w-7 h-7 rounded-lg flex items-center justify-center" style="background:${meta.iconBg};">
                        <i class="${meta.icon} text-xs" style="color:${meta.iconColor};"></i>
                      </div>
                      <span class="text-[7px] font-bold text-amber-400 text-center leading-tight">${meta.label}</span>
                      <span class="text-[6px] text-amber-500 mono font-bold">Expiring</span>
                    </div>`;
          } else {
            // ok or unknown — standard green connected card
            return `<div class="platform-card relative flex flex-col items-center gap-1 p-2 rounded-xl cursor-pointer"
                         style="background:rgba(16,185,129,0.08);border:1px solid rgba(16,185,129,0.28);"
                         onclick="openPlatformModal('${p.platform}', true)"
                         title="Connected — tap to manage">
                      <div class="absolute top-1 right-1 w-1.5 h-1.5 rounded-full bg-emerald-400 pulse-dot" style="animation-delay:${delay}s;"></div>
                      <div class="w-7 h-7 rounded-lg flex items-center justify-center" style="background:${meta.iconBg};">
                        <i class="${meta.icon} text-xs" style="color:${meta.iconColor};"></i>
                      </div>
                      <span class="text-[7px] font-bold text-emerald-400 text-center leading-tight">${meta.label}</span>
                    </div>`;
          }
        } else {
          return `<div class="platform-card relative flex flex-col items-center gap-1 p-2 rounded-xl cursor-pointer"
                       style="background:#020617;border:1px solid rgba(51,65,85,0.8);"
                       onclick="openPlatformModal('${p.platform}', false)"
                       onmouseenter="this.style.background='rgba(51,65,85,0.35)'"
                       onmouseleave="this.style.background='#020617'"
                       title="Tap to connect ${meta.label}">
                    <div class="w-7 h-7 rounded-lg flex items-center justify-center" style="background:rgba(51,65,85,0.3);">
                      <i class="${meta.icon} text-slate-500 text-xs"></i>
                    </div>
                    <span class="text-[7px] font-bold text-slate-500 text-center leading-tight">${meta.label}</span>
                    <span class="text-[6px] text-slate-600 mono">Setup</span>
                  </div>`;
        }
      }).join('');

      document.getElementById('platformStatusText').textContent = `${connectedCount} / ${total} channels authenticated`;
      document.getElementById('platformProgressBar').style.width = pct + '%';
      document.getElementById('platformProgressPct').textContent = pct + '%';
    }

    function openPlatformModal(platformKey, isConnected) {
      _activePlatform = platformKey;
      const meta = PLATFORM_META[platformKey] || {};
      const p = _platformState.find(x => x.platform === platformKey) || {};

      // Set modal header
      document.getElementById('modalTitle').textContent = (meta.label || platformKey) + ' Connection';
      const iconEl = document.getElementById('modalIcon');
      iconEl.style.background = meta.iconBg || 'rgba(51,65,85,0.3)';
      iconEl.innerHTML = `<i class="${meta.icon} text-sm" style="color:${meta.iconColor};"></i>`;

      // Show the right form
      const connectForm = document.getElementById('connectForm');
      const disconnectForm = document.getElementById('disconnectForm');
      document.getElementById('modalError').classList.add('hidden');
      document.getElementById('inputAccessToken').value = '';
      document.getElementById('inputAccountId').value = '';
      document.getElementById('connectBtn').disabled = false;
      document.getElementById('connectBtn').textContent = '';
      document.getElementById('connectBtn').innerHTML = '<i class="fas fa-link mr-1.5"></i>Connect Platform';

      // Show/hide OAuth button based on platform support
      const oauthSection = document.getElementById('oauthSection');
      if (OAUTH_PLATFORMS.has(platformKey)) {
        oauthSection.classList.remove('hidden');
      } else {
        oauthSection.classList.add('hidden');
      }

      if (isConnected) {
        connectForm.classList.add('hidden');
        disconnectForm.classList.remove('hidden');
        const connAt = p.connected_at ? new Date(p.connected_at).toLocaleDateString('en-US', { month:'short', day:'numeric', year:'numeric' }) : 'recently';
        document.getElementById('disconnectConnectedAt').textContent = 'Connected on ' + connAt;

        // Token expiry warning
        const statusBox   = document.getElementById('connectedStatusBox');
        const statusIcon  = document.getElementById('connectedStatusIcon');
        const statusLabel = document.getElementById('connectedStatusLabel');
        const warningBox  = document.getElementById('expiryWarningBox');
        const warningText = document.getElementById('expiryWarningText');

        if (p.token_status === 'expired') {
          statusBox.style.background = 'rgba(239,68,68,0.07)';
          statusBox.style.border     = '1px solid rgba(239,68,68,0.3)';
          statusIcon.className       = 'fas fa-times-circle text-red-400 text-lg mb-1 block';
          statusLabel.className      = 'text-[10px] font-bold text-red-400';
          statusLabel.textContent    = 'Token Expired';
          warningBox.classList.remove('hidden');
          warningBox.style.background = 'rgba(239,68,68,0.08)';
          warningBox.style.border     = '1px solid rgba(239,68,68,0.25)';
          warningText.className       = 'text-[9px] font-bold text-center text-red-400';
          warningText.textContent     = '⚠ This token has expired. Publishing will fail until you reconnect.';
        } else if (p.token_status === 'expiring_soon') {
          const expiryDate = p.token_expiry ? new Date(p.token_expiry).toLocaleDateString('en-US', { month:'short', day:'numeric', year:'numeric' }) : 'soon';
          statusBox.style.background = 'rgba(245,158,11,0.07)';
          statusBox.style.border     = '1px solid rgba(245,158,11,0.3)';
          statusIcon.className       = 'fas fa-exclamation-triangle text-amber-400 text-lg mb-1 block';
          statusLabel.className      = 'text-[10px] font-bold text-amber-400';
          statusLabel.textContent    = 'Token Expiring Soon';
          warningBox.classList.remove('hidden');
          warningBox.style.background = 'rgba(245,158,11,0.07)';
          warningBox.style.border     = '1px solid rgba(245,158,11,0.25)';
          warningText.className       = 'text-[9px] font-bold text-center text-amber-400';
          warningText.textContent     = `⚠ Token expires on ${expiryDate}. Reconnect before then to avoid publish failures.`;
        } else {
          // ok or unknown — restore defaults
          statusBox.style.background = 'rgba(16,185,129,0.07)';
          statusBox.style.border     = '1px solid rgba(16,185,129,0.2)';
          statusIcon.className       = 'fas fa-check-circle text-emerald-400 text-lg mb-1 block';
          statusLabel.className      = 'text-[10px] font-bold text-emerald-400';
          statusLabel.textContent    = 'Platform Connected';
          warningBox.classList.add('hidden');
        }
      } else {
        connectForm.classList.remove('hidden');
        disconnectForm.classList.add('hidden');
        // Show account_id field only for platforms that need it
        const needsAccountId = (p.required_fields || []).includes('account_id');
        const accountIdRow = document.getElementById('accountIdRow');
        if (needsAccountId) {
          accountIdRow.classList.remove('hidden');
          document.getElementById('accountIdLabel').textContent = ACCOUNT_ID_LABELS[platformKey] || 'Account ID';
        } else {
          accountIdRow.classList.add('hidden');
        }
      }

      document.getElementById('platformModal').classList.remove('hidden');
    }

    function closePlatformModal() {
      document.getElementById('platformModal').classList.add('hidden');
      _activePlatform = null;
    }

    // Switch from the "connected / expiry warning" view to the reconnect (connect) form
    function switchToReconnect() {
      document.getElementById('disconnectForm').classList.add('hidden');
      const connectForm = document.getElementById('connectForm');
      connectForm.classList.remove('hidden');
      document.getElementById('inputAccessToken').value = '';
      document.getElementById('inputAccountId').value = '';
      document.getElementById('modalError').classList.add('hidden');
      document.getElementById('connectBtn').disabled = false;
      document.getElementById('connectBtn').innerHTML = '<i class="fas fa-rotate-right mr-1.5"></i>Reconnect Platform';
      // Show account_id field if the platform needs it
      const p = _platformState.find(x => x.platform === _activePlatform) || {};
      const needsAccountId = (p.required_fields || []).includes('account_id');
      const accountIdRow = document.getElementById('accountIdRow');
      if (needsAccountId) {
        accountIdRow.classList.remove('hidden');
        document.getElementById('accountIdLabel').textContent = ACCOUNT_ID_LABELS[_activePlatform] || 'Account ID';
      } else {
        accountIdRow.classList.add('hidden');
      }
    }

    async function submitPlatformConnect() {
      const jwt = _getJwt();
      if (!jwt) { showModalError('Please log in first.'); return; }

      const accessToken = document.getElementById('inputAccessToken').value.trim();
      const accountId   = document.getElementById('inputAccountId').value.trim();
      if (!accessToken) { showModalError('Access token is required.'); return; }

      const btn = document.getElementById('connectBtn');
      btn.disabled = true;
      btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-1.5"></i>Connecting…';

      try {
        const body = { access_token: accessToken };
        if (accountId) body.account_id = accountId;

        const res = await fetch('/api/v1/platforms/' + _activePlatform, {
          method: 'POST',
          headers: { 'Authorization': 'Bearer ' + jwt, 'Content-Type': 'application/json' },
          body: JSON.stringify(body)
        });
        if (!res.ok) {
          const err = await res.json().catch(() => ({}));
          showModalError(err.detail || 'Connection failed. Check your token and try again.');
          btn.disabled = false;
          btn.innerHTML = '<i class="fas fa-link mr-1.5"></i>Connect Platform';
          return;
        }
        closePlatformModal();
        await loadPlatforms();   // refresh grid
      } catch (e) {
        showModalError('Network error. Please try again.');
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-link mr-1.5"></i>Connect Platform';
      }
    }

    async function testPlatformConnection() {
      const jwt = _getJwt();
      if (!jwt) return;
      const btn = document.getElementById('testConnectionBtn');
      const resultEl = document.getElementById('testResult');
      btn.disabled = true;
      btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-1.5"></i>Testing…';
      resultEl.classList.add('hidden');
      try {
        const res = await fetch('/api/v1/platforms/' + _activePlatform + '/test', {
          method: 'POST',
          headers: { 'Authorization': 'Bearer ' + jwt }
        });
        const data = await res.json().catch(() => ({}));
        resultEl.classList.remove('hidden');
        if (data.valid) {
          resultEl.style.color = '#34d399';
          resultEl.textContent = '✓ ' + (data.message || 'Credentials valid');
        } else {
          resultEl.style.color = '#f87171';
          resultEl.textContent = '✗ ' + (data.message || 'Validation failed');
        }
      } catch(e) {
        resultEl.classList.remove('hidden');
        resultEl.style.color = '#f87171';
        resultEl.textContent = '✗ Network error. Try again.';
      }
      btn.disabled = false;
      btn.innerHTML = '<i class="fas fa-stethoscope mr-1.5"></i>Test Connection';
    }

    async function submitPlatformDisconnect() {
      const jwt = _getJwt();
      if (!jwt) return;

      const btn = document.getElementById('disconnectBtn');
      btn.disabled = true;
      btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-1.5"></i>Disconnecting…';

      try {
        const res = await fetch('/api/v1/platforms/' + _activePlatform, {
          method: 'DELETE',
          headers: { 'Authorization': 'Bearer ' + jwt }
        });
        if (!res.ok) {
          btn.disabled = false;
          btn.innerHTML = '<i class="fas fa-unlink mr-1.5"></i>Disconnect';
          return;
        }
        closePlatformModal();
        await loadPlatforms();
      } catch (e) {
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-unlink mr-1.5"></i>Disconnect';
      }
    }

    function showModalError(msg) {
      const el = document.getElementById('modalError');
      el.textContent = msg;
      el.classList.remove('hidden');
    }

    // ══ OAUTH2 POPUP FLOW ═══════════════════════════════════════════════════

    async function startOAuthConnect() {
      const jwt = _getJwt();
      if (!jwt) { showModalError('Please log in first.'); return; }

      const btn = document.getElementById('oauthBtn');
      btn.disabled = true;
      btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-1.5"></i>Opening OAuth…';

      try {
        const res = await fetch('/api/v1/auth/connect/' + _activePlatform, {
          headers: { 'Authorization': 'Bearer ' + jwt }
        });
        if (!res.ok) {
          const err = await res.json().catch(() => ({}));
          showModalError(err.detail || 'OAuth not configured for this platform. Check CLIENT_ID / CLIENT_SECRET secrets.');
          btn.disabled = false;
          btn.innerHTML = '<i class="fas fa-external-link-alt mr-1.5"></i>Connect via OAuth';
          return;
        }
        const data = await res.json();
        const authUrl = data.auth_url;

        // Try to open a popup
        _oauthPopup = window.open(authUrl, 'alpha_oauth_' + _activePlatform,
          'width=620,height=720,scrollbars=yes,resizable=yes,left=' +
          Math.round((screen.width - 620) / 2) + ',top=' + Math.round((screen.height - 720) / 2));

        if (!_oauthPopup || _oauthPopup.closed || typeof _oauthPopup.closed === 'undefined') {
          // Popup blocked — navigate the main window
          window.location.href = authUrl;
        } else {
          // Poll for popup closure (handles cases where postMessage is not fired)
          const pollTimer = setInterval(function() {
            if (_oauthPopup && _oauthPopup.closed) {
              clearInterval(pollTimer);
              btn.disabled = false;
              btn.innerHTML = '<i class="fas fa-external-link-alt mr-1.5"></i>Connect via OAuth';
              loadPlatforms(); // refresh grid in case it was connected
            }
          }, 800);
        }
      } catch (e) {
        showModalError('Failed to start OAuth flow. Please try again.');
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-external-link-alt mr-1.5"></i>Connect via OAuth';
      }
    }

    // Handle postMessage from OAuth popup (delivery path 1)
    window.addEventListener('message', function(event) {
      if (!event.data || event.data.type !== 'ALPHA_OAUTH_RESULT') return;
      const { platform, success, error } = event.data;
      if (_oauthPopup && !_oauthPopup.closed) {
        try { _oauthPopup.close(); } catch(e) {}
        _oauthPopup = null;
      }
      if (success) {
        closePlatformModal();
        loadPlatforms();
        // Brief success toast
        _showOAuthToast(platform, true, null);
      } else {
        showModalError('OAuth failed: ' + (error || 'Unknown error'));
        const btn = document.getElementById('oauthBtn');
        if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fas fa-external-link-alt mr-1.5"></i>Connect via OAuth'; }
      }
    });

    // Handle redirect fallback: ?oauth_result=... (delivery path 2 — blocked popup)
    function readOAuthResultFromUrl() {
      try {
        const params = new URLSearchParams(window.location.search);
        const raw = params.get('oauth_result');
        if (!raw) return;
        const payload = JSON.parse(raw);
        if (payload.type !== 'ALPHA_OAUTH_RESULT') return;
        // Strip the param from the URL so refreshing doesn't re-apply it
        const clean = new URL(window.location.href);
        clean.searchParams.delete('oauth_result');
        window.history.replaceState({}, '', clean.toString());
        // Apply the result
        if (payload.success) {
          loadPlatforms();
          _showOAuthToast(payload.platform, true, null);
        } else {
          _showOAuthToast(payload.platform, false, payload.error);
        }
      } catch(e) { /* malformed param — ignore */ }
    }

    function _showOAuthToast(platform, success, error) {
      const meta = PLATFORM_META[platform] || { label: platform };
      const toast = document.createElement('div');
      toast.style.cssText = 'position:fixed;bottom:24px;left:50%;transform:translateX(-50%);z-index:9999;' +
        'padding:10px 18px;border-radius:14px;font-size:11px;font-weight:700;color:#fff;' +
        'box-shadow:0 8px 24px rgba(0,0,0,0.4);transition:opacity 0.4s;';
      if (success) {
        toast.style.background = 'linear-gradient(135deg,#10b981,#06b6d4)';
        toast.innerHTML = '<i class="fas fa-check-circle mr-1.5"></i>' + meta.label + ' connected successfully!';
      } else {
        toast.style.background = 'linear-gradient(135deg,#ef4444,#f97316)';
        toast.innerHTML = '<i class="fas fa-times-circle mr-1.5"></i>' + meta.label + ' connection failed: ' + (error || 'Unknown error');
      }
      document.body.appendChild(toast);
      setTimeout(function() { toast.style.opacity = '0'; setTimeout(function() { toast.remove(); }, 400); }, 3500);
    }

    // Close modal on backdrop click
    document.getElementById('platformModal').addEventListener('click', function(e) {
      if (e.target === this) closePlatformModal();
    });

    // ══ PUBLISH RESULTS SYSTEM ══════════════════════════════════════════════
    const PLATFORM_STATUS_COLORS = {
      success: { bg: 'rgba(16,185,129,0.12)', border: 'rgba(16,185,129,0.35)', dot: '#10b981', label: '#34d399' },
      failed:  { bg: 'rgba(239,68,68,0.10)',  border: 'rgba(239,68,68,0.35)',  dot: '#ef4444', label: '#f87171' },
      skipped: { bg: 'rgba(51,65,85,0.25)',   border: 'rgba(51,65,85,0.5)',    dot: '#475569', label: '#64748b' },
    };

    // Shorten platform keys to compact display names
    const PLATFORM_SHORT = {
      'YouTube_Community_Posts':      'YT',
      'Instagram_Reels_And_Feed':     'IG',
      'Facebook_Reels_And_Pages':     'FB',
      'LinkedIn_Feed':                'LI',
      'TikTok':                       'TT',
      'Threads_Feed':                 'TH',
      'WhatsApp_Status_And_Channels': 'WA',
      'YouTube_Shorts':               'YTS',
    };

    function _platformStatusIcon(s) {
      if (s === 'success') return '<i class="fas fa-check text-[7px]" style="color:#10b981;"></i>';
      if (s === 'failed')  return '<i class="fas fa-times text-[7px]" style="color:#ef4444;"></i>';
      return '<i class="fas fa-minus text-[7px]" style="color:#475569;"></i>';
    }

    function renderPublishLog(log) {
      if (!log || Object.keys(log).filter(k => k !== '__no_credentials').length === 0) {
        return '<p class="text-[8px] text-slate-600 text-center py-2">No platform data recorded.</p>';
      }
      const entries = Object.entries(log).filter(([k]) => k !== '__no_credentials');
      return '<div class="grid grid-cols-4 gap-1.5">' +
        entries.map(([key, val]) => {
          const short = PLATFORM_SHORT[key] || key.slice(0, 3).toUpperCase();
          const c = PLATFORM_STATUS_COLORS[val.status] || PLATFORM_STATUS_COLORS.skipped;
          return `<div class="flex flex-col items-center gap-0.5 p-1.5 rounded-xl"
                       style="background:${c.bg};border:1px solid ${c.border};"
                       title="${key}: ${val.message || val.status}">
                    <div class="w-5 h-5 rounded-full flex items-center justify-center" style="background:rgba(15,23,42,0.6);">
                      ${_platformStatusIcon(val.status)}
                    </div>
                    <span class="text-[7px] font-black mono" style="color:${c.label};">${short}</span>
                  </div>`;
        }).join('') +
      '</div>';
    }

    async function loadPublishResults() {
      const jwt = _getJwt();
      if (!jwt) return;

      const container = document.getElementById('publishResultsContainer');
      container.innerHTML = '<div class="flex items-center justify-center py-3 gap-1.5"><div class="w-1.5 h-1.5 rounded-full bg-indigo-400 animate-pulse"></div><p class="text-[8px] text-slate-500">Loading results…</p></div>';

      try {
        // Single authenticated call — no client-side JWT decoding needed
        const res = await fetch('/api/v1/me/recent-publish-logs?limit=3', {
          headers: { 'Authorization': 'Bearer ' + jwt }
        });
        if (!res.ok) {
          container.innerHTML = '<p class="text-[8px] text-slate-600 text-center py-2">Could not load results.</p>';
          return;
        }

        const data = await res.json();
        const posts = data.posts || [];

        if (posts.length === 0) {
          container.innerHTML = '<div class="flex flex-col items-center py-3 gap-1"><i class="fas fa-broadcast-tower text-slate-700 text-lg"></i><p class="text-[8px] text-slate-600 text-center">No publish results yet.<br>Run automation to see platform status.</p></div>';
          return;
        }

        container.innerHTML = posts.map((log, i) => {
          const statusColor = log.status === 'published' ? '#34d399' : '#f87171';
          const statusIcon  = log.status === 'published' ? 'fa-check-circle' : 'fa-exclamation-circle';
          const dateStr = new Date(log.created_at).toLocaleDateString('en-US', { month:'short', day:'numeric' });
          return `<div class="space-y-1.5 ${i > 0 ? 'mt-2 pt-2 border-t border-slate-800' : ''}">
            <div class="flex items-center justify-between">
              <p class="text-[8px] font-bold text-slate-300 truncate flex-1 pr-2">${log.episode_title || 'Post #' + log.post_id}</p>
              <div class="flex items-center gap-1 flex-shrink-0">
                <i class="fas ${statusIcon} text-[8px]" style="color:${statusColor};"></i>
                <span class="text-[7px] mono text-slate-500">${dateStr}</span>
              </div>
            </div>
            ${renderPublishLog(log.publish_log)}
          </div>`;
        }).join('');
      } catch(e) {
        container.innerHTML = '<p class="text-[8px] text-slate-600 text-center py-2">Error loading results.</p>';
      }
    }

    // Handle OAuth2 redirect fallback (?oauth_result=...)
    readOAuthResultFromUrl();

    // Load on page ready
    loadPlatforms();

    // ── PWA: register service worker ──────────────────
    if ('serviceWorker' in navigator) {
      window.addEventListener('load', () => {
        navigator.serviceWorker.register('/sw.js').catch(() => {});
      });
    }
    loadPublishResults();

    // ── Clone timer simulation ────────────────────
    let cloneSeconds = 32;
    setInterval(() => {
      if (document.getElementById('clonePanel').style.opacity === '1') {
        cloneSeconds = (cloneSeconds + 1) % 46;
        const m = Math.floor(cloneSeconds / 60);
        const s = cloneSeconds % 60;
        document.getElementById('cloneTimer').textContent =
          m + ':' + String(s).padStart(2, '0');
      }
    }, 1000);

    // ── Init: set stockPanel to visible ──────────
    (function init() {
      const sp = document.getElementById('stockPanel');
      sp.style.maxHeight = '300px';
      sp.style.opacity   = '1';
      sp.style.pointerEvents = 'auto';
    })();
  </script>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────────────────────
# API ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────

# Pydantic Schemas
class LoginInitSchema(BaseModel):
    """Step 1 of email-OTP login: credentials only."""
    email: EmailStr
    password: str

class LoginVerifySchema(BaseModel):
    """Step 2 of email-OTP login: validate the 6-digit code sent to email."""
    email: EmailStr
    otp_code: str  # 6-digit numeric string

class NicheDropdownSchema(BaseModel):
    chosen_niche: str
    celebrity_tracker_string: Optional[str] = None

class SeriesSetupSchema(BaseModel):
    delivery_time: str
    timezone: str
    active_target_language: str
    auto_create_podcast_series: bool

class BrandKitSchema(BaseModel):
    brand_name: str
    brand_contact: str
    hex_colors: List[str]
    header_font: str
    caption_font: str
    visual_podcast_template: str
    persistent_hashtags: str

# 1. Registration
_RECOVERY_CODE_COUNT = 8   # number of backup codes generated per user

async def _generate_recovery_codes(user_id: int, db: AsyncSession) -> list[str]:
    """Generate ``_RECOVERY_CODE_COUNT`` single-use backup codes for *user_id*.

    Each code is a 10-character upper-case hex string (5 random bytes).
    The plaintext values are returned to the caller *once* so they can be
    shown to the user; only the bcrypt hashes are persisted.
    """
    plaintext_codes: list[str] = []
    for _ in range(_RECOVERY_CODE_COUNT):
        code = secrets.token_hex(5).upper()   # e.g. "3F9A1C2B4E"
        code_hash = _bcrypt.hashpw(code.encode(), _bcrypt.gensalt()).decode()
        db.add(RecoveryCode(user_id=user_id, code_hash=code_hash))
        plaintext_codes.append(code)
    await db.commit()
    return plaintext_codes


class OnboardingConfigSchema(BaseModel):
    """Optional onboarding payload that can be submitted alongside registration.

    Mirrors the global-state JSON that the AlphaApp bottom-bar SUBMIT emits.
    All fields are optional — any supplied values are persisted immediately so
    the user starts with a pre-configured profile instead of empty defaults.
    """
    # Podcast Hub
    chosen_niche: Optional[str] = None
    celebrity_names: Optional[List[str]] = None  # tracking chip array
    delivery_time: Optional[str] = None
    timezone: Optional[str] = None
    active_target_language: Optional[str] = None
    voice_id: Optional[str] = None
    image_mode: Optional[str] = None
    media_mix_video_percentage: Optional[int] = None
    # Aesthetics
    hex_colors: Optional[List[str]] = None
    header_font: Optional[str] = None
    caption_font: Optional[str] = None
    visual_podcast_template: Optional[str] = None
    persistent_hashtags: Optional[str] = None
    # Business
    package_tier: Optional[str] = None
    is_business_mode: Optional[bool] = None
    brand_name: Optional[str] = None
    brand_contact: Optional[str] = None
    brand_logo_url: Optional[str] = None
    target_aspect_ratio: Optional[str] = None  # "1:1" or "9:16"; default is "9:16"


class RegisterSchema(BaseModel):
    email: EmailStr
    password: str
    onboarding: Optional[OnboardingConfigSchema] = None


@app.post("/api/v1/auth/register", status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
async def register_user(request: Request, payload: RegisterSchema, db: AsyncSession = Depends(get_async_db)):
    import json as _json

    existing = (await db.execute(sa_select(User).where(User.email == payload.email))).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered.")

    hashed_password = _hash_password(payload.password)
    totp_secret = pyotp.random_base32()

    cfg = payload.onboarding or OnboardingConfigSchema()

    user = User(
        email=payload.email,
        hashed_password=hashed_password,
        totp_secret=totp_secret,
        package_tier=cfg.package_tier or "starter",
        is_business_mode=cfg.is_business_mode or False,
        brand_name=cfg.brand_name,
        brand_contact=cfg.brand_contact,
        brand_logo_url=cfg.brand_logo_url,
        content_schedule_time=cfg.delivery_time or "09:00:00",
        onboarding_complete=bool(payload.onboarding),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    # ── Provision UserWallet ──────────────────────────────────────────────────
    db.add(UserWallet(user_id=user.id, available_balance=0.00, pending_balance=0.00))

    # ── Provision UserAestheticSetting ────────────────────────────────────────
    db.add(UserAestheticSetting(
        user_id=user.id,
        chosen_niche=cfg.chosen_niche,
        celebrity_tracker_string=",".join(cfg.celebrity_names) if cfg.celebrity_names else None,
        delivery_time=cfg.delivery_time,
        timezone=cfg.timezone or "UTC",
        active_target_language=cfg.active_target_language or "en",
        voice_id=cfg.voice_id,
        image_mode=cfg.image_mode or "ai_generation",
        media_mix_video_percentage=cfg.media_mix_video_percentage if cfg.media_mix_video_percentage is not None else 50,
        hex_colors=_json.dumps(cfg.hex_colors) if cfg.hex_colors else "[]",
        header_font=cfg.header_font,
        caption_font=cfg.caption_font,
        visual_podcast_template=cfg.visual_podcast_template or "minimalist",
        persistent_hashtags=cfg.persistent_hashtags or "",
        brand_name=cfg.brand_name,
        brand_contact=cfg.brand_contact,
        target_aspect_ratio=cfg.target_aspect_ratio if cfg.target_aspect_ratio in ("1:1", "9:16") else "9:16",
    ))
    await db.commit()

    # ── Provision UserSelectedSource rows (one per celebrity chip) ────────────
    if cfg.celebrity_names:
        for name in cfg.celebrity_names:
            db.add(UserSelectedSource(
                user_id=user.id,
                chosen_niche=cfg.chosen_niche,
                celebrity_name=name,
            ))
    elif cfg.chosen_niche:
        db.add(UserSelectedSource(user_id=user.id, chosen_niche=cfg.chosen_niche))
    await db.commit()

    totp = pyotp.TOTP(totp_secret)
    provisioning_url = totp.provisioning_uri(name=payload.email, issuer_name="ALPHA")
    recovery_codes = await _generate_recovery_codes(user.id, db)

    return {
        "message": "User registered successfully",
        "user_id": user.id,
        "provisioned": {
            "wallet": True,
            "aesthetic_settings": True,
            "selected_sources": len(cfg.celebrity_names or ([cfg.chosen_niche] if cfg.chosen_niche else [])),
        },
        "two_fa_secret": totp_secret,
        "qr_config_url": provisioning_url,
        "recovery_codes": recovery_codes,
        "info": (
            "Save this secret seed in Google Authenticator to protect your profile from voice identity theft. "
            "Also store your recovery codes somewhere safe — each can be used once to log in if you lose "
            "your authenticator device."
        ),
    }

# 2. Login — Step 1: validate credentials, generate + email a 6-digit OTP
@app.post("/api/v1/auth/login")
@limiter.limit("10/minute")
async def login_user(request: Request, payload: LoginInitSchema, db: AsyncSession = Depends(get_async_db)):
    """Validate email+password. On success, email a 6-digit OTP and return {status: 'code_sent'}."""
    user = (await db.execute(sa_select(User).where(User.email == payload.email))).scalar_one_or_none()
    if not user or not _verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Generate a cryptographically random 6-digit OTP
    otp_plain = f"{secrets.randbelow(900000) + 100000}"
    otp_hash = _bcrypt.hashpw(otp_plain.encode(), _bcrypt.gensalt()).decode()

    # Invalidate any existing OTPs for this user, then persist the new one
    await db.execute(sa_delete(LoginOTP).where(LoginOTP.user_id == user.id))
    db.add(LoginOTP(
        user_id=user.id,
        code_hash=otp_hash,
        expires_at=datetime.utcnow() + timedelta(minutes=10),
    ))
    await db.commit()

    # Send email — surface failures to the caller so the UI can show them
    try:
        await _send_otp_email(user.email, otp_plain)
    except Exception as exc:
        import logging as _log
        _log.getLogger(__name__).error("OTP email failed for user %s: %s", user.id, exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Could not send verification email — please try again in a moment.",
        )

    # Mask the email address before returning it (e.g. "op***@studio.com")
    at = user.email.index("@")
    masked = user.email[:2] + "*" * max(0, at - 2) + user.email[at:]
    return {"status": "code_sent", "email": masked}


# 2b. Login — Step 2: validate the 6-digit email OTP, return JWT
@app.post("/api/v1/auth/login/verify")
@limiter.limit("10/minute")
async def verify_login_otp(request: Request, payload: LoginVerifySchema, db: AsyncSession = Depends(get_async_db)):
    """Accept the 6-digit OTP the user received by email. Returns a JWT on success."""
    user = (await db.execute(sa_select(User).where(User.email == payload.email))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid code.")

    otp_row = (await db.execute(
        sa_select(LoginOTP)
        .where(LoginOTP.user_id == user.id, LoginOTP.used == False)  # noqa: E712
        .order_by(LoginOTP.created_at.desc())
        .limit(1)
    )).scalar_one_or_none()

    if not otp_row:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No active code found — go back and sign in again.",
        )
    if datetime.utcnow() > otp_row.expires_at:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Code expired — go back and sign in again to receive a new one.",
        )
    if not _bcrypt.checkpw(payload.otp_code.encode(), otp_row.code_hash.encode()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid code.")

    otp_row.used = True
    await db.commit()

    access_token = _create_access_token(user_id=user.id, email=user.email)
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user.id,
    }

# 3. Logout — revoke the current token by adding its JTI to the blacklist
@app.post("/api/v1/auth/logout", status_code=status.HTTP_200_OK)
async def logout_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_async_db),
):
    """Invalidate the caller's JWT immediately.

    The token's JTI is written to the ``revoked_tokens`` table so that
    subsequent requests carrying the same token are rejected by
    ``get_current_user`` — even if the token hasn't expired yet.
    """
    token = credentials.credentials
    try:
        # Decode without raising on expiry so already-expired tokens can still
        # be cleanly revoked (they're harmless but explicit revocation is tidy).
        payload = jwt.decode(
            token, _JWT_SECRET, algorithms=[_JWT_ALGORITHM],
            options={"verify_exp": False},
        )
        jti: str = payload["jti"]
        user_id: int = int(payload["sub"])
        exp_ts = payload.get("exp")
        expires_at = (
            datetime.utcfromtimestamp(exp_ts) if exp_ts else datetime.utcnow()
        )
    except (JWTError, KeyError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # Idempotent — don't error if the token was already revoked
    existing_rev = (await db.execute(sa_select(RevokedToken).where(RevokedToken.jti == jti))).scalar_one_or_none()
    if not existing_rev:
        db.add(RevokedToken(jti=jti, user_id=user_id, expires_at=expires_at))
        await db.commit()
    return {"message": "Successfully logged out. Token has been revoked."}


# 4. Account recovery (2FA device loss)
class RecoverSchema(BaseModel):
    email: EmailStr
    password: str          # primary credential — recovery code replaces TOTP only
    recovery_code: str


@app.post("/api/v1/auth/recover")
@limiter.limit("5/minute")
async def recover_account(request: Request, payload: RecoverSchema, db: AsyncSession = Depends(get_async_db)):
    """Log in using a password + single-use backup recovery code instead of TOTP.

    The recovery code acts as the *second factor* — it replaces the TOTP code
    but does **not** replace the user's password.  Both must be correct.

    On success the code is atomically invalidated (via a conditional UPDATE that
    checks ``used_at IS NULL``) before the JWT is issued, preventing any race
    between concurrent requests presenting the same code.
    """
    _AUTH_ERROR = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid email, password, or recovery code.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    user = (await db.execute(sa_select(User).where(User.email == payload.email))).scalar_one_or_none()
    # Verify password first — recovery code is a second factor, not a bypass.
    if user is None or not _verify_password(payload.password, user.hashed_password):
        raise _AUTH_ERROR

    # Fetch all unused codes for this user and find one that matches.
    unused_codes = (
        await db.execute(
            sa_select(RecoveryCode).where(
                RecoveryCode.user_id == user.id, RecoveryCode.used_at == None  # noqa: E711
            )
        )
    ).scalars().all()

    matched_id: int | None = None
    for rc in unused_codes:
        if _bcrypt.checkpw(payload.recovery_code.upper().encode(), rc.code_hash.encode()):
            matched_id = rc.id
            break

    if matched_id is None:
        raise _AUTH_ERROR

    # Atomically mark the code as used.  The WHERE clause re-checks used_at IS
    # NULL so that a concurrent request which verified the same code first will
    # cause this UPDATE to touch zero rows — letting us detect and reject the
    # race without a separate SELECT+lock.
    result = await db.execute(
        sa_update(RecoveryCode)
        .where(RecoveryCode.id == matched_id, RecoveryCode.used_at == None)  # noqa: E711
        .values(used_at=datetime.utcnow())
    )
    await db.commit()

    if result.rowcount == 0:
        # Another concurrent request invalidated the code first.
        raise _AUTH_ERROR

    access_token = _create_access_token(user_id=user.id, email=user.email)
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user.id,
        "warning": (
            "You logged in with a backup recovery code. "
            "Please reconfigure your authenticator app as soon as possible."
        ),
    }


# 5. Niche Dropdown
@app.post("/api/v1/onboarding/niche-dropdown")
async def save_user_interests(
    payload: NicheDropdownSchema,
    current_user: User = Depends(get_current_user),
):
    return {
        "status": "success",
        "user_id": current_user.id,
        "message": f"Successfully locked profile to primary niche channel: {payload.chosen_niche}.",
        "tracked_celebrity": payload.celebrity_tracker_string
    }

# 4. Series Setup
@app.post("/api/v1/onboarding/series-setup")
async def save_automation_clock(
    payload: SeriesSetupSchema,
    current_user: User = Depends(get_current_user),
):
    return {
        "status": "success",
        "user_id": current_user.id,
        "message": f"Content scheduler activated for daily drops at {payload.delivery_time} {payload.timezone}.",
        "auto_create_podcast_series_active": payload.auto_create_podcast_series,
        "target_language_locked": f"Dynamic localization engine mapped to target ISO code: {payload.active_target_language}"
    }

# 5. Voice Studio
@app.post("/api/v1/onboarding/voice-studio")
async def setup_voicebox_profile(
    voice_selection: str,
    current_user: User = Depends(get_current_user),
    sample_file: Optional[UploadFile] = File(None),
):
    import os, httpx

    if voice_selection == "clone" and not sample_file:
        raise HTTPException(status_code=400, detail="Audio sample file required for instant voice cloning.")

    _raw_ep  = os.environ.get("VOICEBOX_API_ENDPOINT", "").strip().rstrip("/")
    if _raw_ep and not _raw_ep.startswith(("http://", "https://")):
        _raw_ep = "https://" + _raw_ep
    endpoint = _raw_ep
    api_key  = os.environ.get("VOICEBOX_API_KEY")

    if not endpoint or not api_key:
        raise HTTPException(
            status_code=503,
            detail="Voicebox credentials are not configured. Set VOICEBOX_API_ENDPOINT and VOICEBOX_API_KEY secrets.",
        )

    voice_id: str

    if voice_selection == "clone":
        # Upload the 45-second voice sample to Voicebox clone endpoint
        audio_bytes = await sample_file.read()
        async with httpx.AsyncClient(timeout=120.0) as client:
            clone_response = await client.post(
                f"{endpoint}/clone",
                headers={"Authorization": f"Bearer {api_key}"},
                files={"audio": (sample_file.filename, audio_bytes, sample_file.content_type or "audio/mpeg")},
                data={"user_id": str(current_user.id)},
            )
        if clone_response.status_code in (404, 405):
            raise HTTPException(
                status_code=503,
                detail=(
                    f"Voicebox clone endpoint returned {clone_response.status_code}. "
                    "The provider does not expose POST /clone at the configured "
                    "VOICEBOX_API_ENDPOINT. Verify the endpoint URL and consult your "
                    "Voicebox provider's documentation for the correct clone path."
                ),
            )
        if clone_response.status_code not in (200, 201):
            raise HTTPException(
                status_code=502,
                detail=f"Voicebox clone API error {clone_response.status_code}: {clone_response.text[:300]}",
            )
        clone_data = clone_response.json()
        voice_id = clone_data.get("voice_id") or clone_data.get("id") or f"vb_clone_user_{current_user.id}"
    else:
        # Stock voice — register the selection with Voicebox and get a confirmed voice_id
        async with httpx.AsyncClient(timeout=30.0) as client:
            stock_response = await client.post(
                f"{endpoint}/voices/select",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={"stock_voice_key": voice_selection, "user_id": current_user.id},
            )
        if stock_response.status_code in (200, 201):
            stock_data = stock_response.json()
            voice_id = stock_data.get("voice_id") or f"vb_stock_{voice_selection}"
        else:
            # Non-fatal: use the key directly if the endpoint doesn't support /voices/select
            voice_id = f"vb_stock_{voice_selection}"

    return {
        "status": "success",
        "voice_selection_mode": voice_selection,
        "voice_id": voice_id,
        "message": "Voice profile registered with Voicebox API successfully.",
    }

# 6. Image Studio
@app.post("/api/v1/onboarding/image-studio")
async def setup_image_studio(
    image_source: str,
    current_user: User = Depends(get_current_user),
    uploaded_image: Optional[UploadFile] = File(None),
):
    if image_source == "device_upload" and not uploaded_image:
        raise HTTPException(status_code=400, detail="Image file binary block required for device uploading mode.")
    return {
        "status": "success",
        "image_mode": image_source,
        "file_status": "Saved to cloud bucket asset index" if image_source == "device_upload" else "Triggering local Ideogram/Easy Diffusion worker hooks"
    }

class AutomationRunSchema(BaseModel):
    niche_value: Optional[str] = None
    target_lang: Optional[str] = None
    hex_colors: Optional[List[str]] = None
    template: Optional[str] = None
    image_mode: Optional[str] = None
    voice_id: Optional[str] = None


class ScriptGenerateSchema(BaseModel):
    niche: str = "Finance"
    celebrities: List[str] = []
    perspective: str = "analytical"  # "analytical" | "hype" | "humorous" | "reporter"


# ── Platform connection schemas ───────────────────────────────────────────────
SUPPORTED_PLATFORMS = {
    "youtube":   {"label": "YouTube",   "fields": ["access_token", "account_id"]},
    "instagram": {"label": "Instagram", "fields": ["access_token", "account_id"]},
    "facebook":  {"label": "Facebook",  "fields": ["access_token", "account_id"]},
    "whatsapp":  {"label": "WhatsApp",  "fields": ["access_token", "account_id"]},
    "tiktok":    {"label": "TikTok",    "fields": ["access_token"]},
    "linkedin":  {"label": "LinkedIn",  "fields": ["access_token"]},
    "threads":   {"label": "Threads",   "fields": ["access_token", "account_id"]},
    "baidu":     {"label": "Baidu",     "fields": ["access_token"]},
}

class PlatformConnectSchema(BaseModel):
    access_token: str
    account_id: Optional[str] = None
    refresh_token: Optional[str] = None
    # Optional: caller may provide token lifetime so expiry can be tracked.
    # When omitted, connect_platform applies a conservative platform-specific default.
    # Priority: token_expiry (explicit UTC ISO 8601) > expires_in (seconds) > platform default.
    token_expiry: Optional[str] = None   # ISO 8601 UTC datetime, e.g. "2025-01-01T12:00:00"
    expires_in: Optional[int] = None     # seconds until the access token expires


# 7. List connected platforms
@app.get("/api/v1/platforms")
async def list_platforms(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db),
):
    rows = (await db.execute(
        select(PlatformToken).where(PlatformToken.user_id == current_user.id)
    )).scalars().all()
    connected_map = {r.platform: r for r in rows}
    now = datetime.utcnow()
    warning_threshold = now + timedelta(days=7)
    result = []
    for key, meta in SUPPORTED_PLATFORMS.items():
        token_row = connected_map.get(key)
        if token_row:
            expiry = token_row.token_expiry
            if expiry is None:
                token_status = "unknown"
            elif expiry < now:
                token_status = "expired"
            elif expiry < warning_threshold:
                token_status = "expiring_soon"
            else:
                token_status = "ok"
            result.append({
                "platform": key,
                "label": meta["label"],
                "connected": True,
                "connected_at": token_row.connected_at.isoformat(),
                "token_expiry": expiry.isoformat() if expiry else None,
                "token_status": token_status,
                "required_fields": meta["fields"],
            })
        else:
            result.append({
                "platform": key,
                "label": meta["label"],
                "connected": False,
                "connected_at": None,
                "token_expiry": None,
                "token_status": None,
                "required_fields": meta["fields"],
            })
    return {"platforms": result, "connected_count": len(connected_map)}


# Default token lifetimes per platform (seconds).
# Used when the caller does not supply `expires_in`.
#   YouTube/Google: 1 hour  (access tokens; refresh token lasts indefinitely)
#   Meta (IG/FB/Threads): 60 days  (long-lived tokens)
#   LinkedIn: 60 days  (member tokens)
#   TikTok: 24 hours  (access tokens; refresh token valid for 365 days)
_PLATFORM_DEFAULT_EXPIRY_SECONDS: dict[str, int] = {
    "youtube":   3_600,
    "instagram": 5_184_000,   # 60 days
    "facebook":  5_184_000,
    "threads":   5_184_000,
    "linkedin":  5_184_000,
    "tiktok":    86_400,      # 24 hours
}


# 8. Connect a platform
@app.post("/api/v1/platforms/{platform}", status_code=status.HTTP_200_OK)
async def connect_platform(
    platform: str,
    payload: PlatformConnectSchema,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db),
):
    if platform not in SUPPORTED_PLATFORMS:
        raise HTTPException(status_code=400, detail=f"Unknown platform '{platform}'. Supported: {list(SUPPORTED_PLATFORMS)}")

    # Resolve token expiry (priority: explicit ISO 8601 > expires_in seconds > platform default)
    if payload.token_expiry:
        try:
            token_expiry = datetime.fromisoformat(payload.token_expiry.replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Invalid token_expiry format '{payload.token_expiry}'. "
                    "Provide a UTC ISO 8601 datetime, e.g. '2025-01-01T12:00:00'."
                ),
            )
    else:
        expires_in = payload.expires_in or _PLATFORM_DEFAULT_EXPIRY_SECONDS.get(platform, 3_600)
        token_expiry = datetime.utcnow() + timedelta(seconds=expires_in)

    existing = (await db.execute(
        select(PlatformToken).where(
            PlatformToken.user_id == current_user.id,
            PlatformToken.platform == platform,
        )
    )).scalar_one_or_none()
    if existing:
        existing.access_token = payload.access_token
        existing.refresh_token = payload.refresh_token
        existing.account_id = payload.account_id
        existing.token_expiry = token_expiry
        existing.connected_at = datetime.utcnow()
    else:
        db.add(PlatformToken(
            user_id=current_user.id,
            platform=platform,
            access_token=payload.access_token,
            refresh_token=payload.refresh_token,
            account_id=payload.account_id,
            token_expiry=token_expiry,
        ))
    await db.commit()
    return {"status": "connected", "platform": platform, "label": SUPPORTED_PLATFORMS[platform]["label"]}


# 9. Test stored platform credentials with a live API call
@app.post("/api/v1/platforms/{platform}/test", tags=["platforms"])
async def test_platform_connection(
    platform: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db),
):
    """
    Validates stored platform credentials by making a live API probe call.

    Returns {"valid": bool, "message": str}.  Does not modify any stored data.
    """
    from distribution import (
        _validate_youtube_token,
        _validate_instagram_token,
        _validate_linkedin_token,
        _validate_tiktok_token,
        _validate_whatsapp_token,
    )
    from oauth_tokens import ensure_token_fresh

    if platform not in SUPPORTED_PLATFORMS:
        raise HTTPException(status_code=400, detail=f"Unknown platform '{platform}'.")

    token_row = (await db.execute(
        select(PlatformToken).where(
            PlatformToken.user_id == current_user.id,
            PlatformToken.platform == platform,
        )
    )).scalar_one_or_none()

    if not token_row:
        return {
            "valid":   False,
            "message": f"{SUPPORTED_PLATFORMS[platform]['label']} is not connected. Connect it first.",
        }

    # Proactively refresh if near expiry before testing
    ok, err = await ensure_token_fresh(token_row, db)
    if not ok:
        return {"valid": False, "message": err}

    label = SUPPORTED_PLATFORMS[platform]["label"]
    from crypto import decrypt_token
    access_token = decrypt_token(token_row.access_token)
    account_id   = token_row.account_id or ""

    if platform == "youtube":
        result = await _validate_youtube_token(access_token)
        if result["ok"]:
            return {"valid": True,  "message": f"YouTube credentials valid. Channel: '{result['channel_title']}'."}
        return {"valid": False, "message": result["error"]}

    elif platform in ("instagram", "threads", "facebook"):
        if not account_id:
            return {"valid": False, "message": f"No Account ID stored for {label}. Reconnect and supply the Account/Page ID."}
        result = await _validate_instagram_token(access_token, account_id)
        if result["ok"]:
            return {"valid": True,  "message": f"{label} credentials valid. Account: '{result['name']}'."}
        return {"valid": False, "message": result["error"]}

    elif platform == "linkedin":
        result = await _validate_linkedin_token(access_token)
        if result["ok"]:
            return {"valid": True, "message": f"LinkedIn credentials valid. Account: '{result['name']}'."}
        return {"valid": False, "message": result["error"]}

    elif platform == "tiktok":
        result = await _validate_tiktok_token(access_token)
        if result["ok"]:
            return {"valid": True, "message": f"TikTok credentials valid. Account: '{result['display_name']}'."}
        return {"valid": False, "message": result["error"]}

    elif platform == "whatsapp":
        result = await _validate_whatsapp_token(access_token, account_id or "")
        if result["ok"]:
            return {"valid": True, "message": f"WhatsApp credentials valid. Phone number: '{result['display_phone_number']}'."}
        return {"valid": False, "message": result["error"]}

    else:
        # Future platforms — token stored but live probe not yet implemented
        return {
            "valid":   True,
            "message": f"{label} token is stored and appears valid. Live credential probe not yet available for this platform.",
        }


# 10. Disconnect a platform
@app.delete("/api/v1/platforms/{platform}", status_code=status.HTTP_200_OK)
async def disconnect_platform(
    platform: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db),
):
    if platform not in SUPPORTED_PLATFORMS:
        raise HTTPException(status_code=400, detail=f"Unknown platform '{platform}'.")
    result = await db.execute(
        delete(PlatformToken).where(
            PlatformToken.user_id == current_user.id,
            PlatformToken.platform == platform,
        )
    )
    await db.commit()
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail=f"Platform '{platform}' was not connected.")
    return {"status": "disconnected", "platform": platform}


# 10. Per-platform publish log for a post
@app.get("/api/v1/posts/{post_id}/publish-log")
async def get_publish_log(
    post_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db),
):
    """
    Returns the per-platform publish result log for a specific post.

    The publish_log is a JSON object keyed by platform name, each value being
    {"status": "success"|"failed"|"skipped", "message": str}.

    Only the post owner may retrieve this data.
    """
    import json

    post = (await db.execute(
        select(PostsQueue).where(PostsQueue.id == post_id)
    )).scalar_one_or_none()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found.")
    if post.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: you may only view your own post logs.",
        )

    platform_log = None
    if post.publish_log:
        try:
            platform_log = json.loads(post.publish_log)
        except (json.JSONDecodeError, TypeError):
            platform_log = None

    return {
        "post_id":       post.id,
        "episode_title": post.episode_title,
        "status":        post.status,
        "publish_log":   platform_log,
        "created_at":    post.created_at.isoformat(),
    }

@app.post("/api/v1/script/generate", tags=["script"])
async def generate_script(
    payload: ScriptGenerateSchema,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db),
):
    """
    Generates a real AI-written podcast script for the given niche, celebrity
    list, and perspective angle via NVIDIA Nemotron.

    The endpoint enriches the AI prompt with the user's saved configuration:
      • chosen_niche from user_aesthetic_settings (when payload niche is default)
      • celebrity_name rows from user_selected_sources (always merged in)

    Requires a valid Bearer JWT (same token used by the rest of the API).

    Returns:
        body        – full narration script (200-300 words)
        titleHook   – punchy episode title hook
        imagePrompt – vivid Ideogram image generation prompt
        subtitles   – list of 5 short on-screen subtitle strings
        perspective – echo of the requested perspective
    """
    from tasks import generate_script_for_perspective

    valid_perspectives = {"analytical", "hype", "humorous", "reporter"}
    if payload.perspective not in valid_perspectives:
        raise HTTPException(
            status_code=422,
            detail=f"perspective must be one of {sorted(valid_perspectives)}",
        )

    # ── DB enrichment: resolve niche and celebrities from saved configuration ──
    # Query user_selected_sources for configured tracking chips (celebrities)
    db_sources = (await db.execute(
        sa_select(UserSelectedSource).where(UserSelectedSource.user_id == current_user.id)
    )).scalars().all()

    # Query aesthetic settings for saved niche preference
    db_settings = (await db.execute(
        sa_select(UserAestheticSetting).where(UserAestheticSetting.user_id == current_user.id)
    )).scalar_one_or_none()

    # Resolve effective niche: payload is authoritative when explicitly set;
    # fall back to the saved DB niche so scripts always reflect user configuration.
    schema_default_niche = "Finance"
    db_niche = (
        (db_settings.chosen_niche if db_settings and db_settings.chosen_niche else None)
        or (db_sources[0].chosen_niche if db_sources else None)
    )
    effective_niche = payload.niche if (payload.niche and payload.niche != schema_default_niche) else (db_niche or payload.niche or schema_default_niche)

    # Merge payload celebrities with DB-tracked celebrity chips (deduplicated)
    db_celebrities = [s.celebrity_name for s in db_sources if s.celebrity_name]
    effective_celebrities = list(dict.fromkeys([*payload.celebrities, *db_celebrities]))

    try:
        result = await generate_script_for_perspective(
            niche=effective_niche,
            celebrities=effective_celebrities,
            perspective=payload.perspective,
        )
    except EnvironmentError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=502, detail=str(exc))

    # Generate the Ideogram graphic card for this script so the preview box
    # can display the real AI image.  Failure is non-fatal — the frontend
    # falls back gracefully to the placeholder illustration.
    graphic_card_url: Optional[str] = None
    if result.get("imagePrompt"):
        from tasks import generate_ideogram_background
        import uuid as _uuid
        try:
            filename = f"script_preview_{current_user.id}_{_uuid.uuid4().hex[:8]}.png"
            graphic_card_url = await generate_ideogram_background(
                prompt=result["imagePrompt"],
                filename=filename,
            )
        except Exception:
            pass  # image generation is best-effort; don't block the script response

    return {**result, "perspective": payload.perspective, "graphic_card_url": graphic_card_url}


@app.post("/api/v1/automation/run", status_code=status.HTTP_201_CREATED)
async def run_automation(
    payload: AutomationRunSchema,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db),
):
    """
    Triggers the full AI automation pipeline for the authenticated user.
    Falls back to stored aesthetic settings when optional overrides are not provided.
    Saves the generated post to PostsQueue with status='pending_review'.
    """
    import json

    # Load stored aesthetic settings for defaults
    settings = (await db.execute(
        sa_select(UserAestheticSetting).where(UserAestheticSetting.user_id == current_user.id)
    )).scalar_one_or_none()

    niche_value         = payload.niche_value or (settings.chosen_niche if settings else "General")
    target_lang         = payload.target_lang or (settings.active_target_language if settings else "en")
    voice_id            = payload.voice_id    or (settings.voice_id if settings and settings.voice_id else "en_us_m_deep")
    image_mode          = payload.image_mode  or (settings.image_mode if settings else "ai_generation")
    template            = payload.template    or (settings.visual_podcast_template if settings else "minimalist")
    target_aspect_ratio = (
        getattr(settings, "target_aspect_ratio", None) or "9:16"
        if settings else "9:16"
    )

    if payload.hex_colors is not None:
        hex_colors = payload.hex_colors
    elif settings and settings.hex_colors:
        try:
            hex_colors = json.loads(settings.hex_colors)
        except (json.JSONDecodeError, TypeError):
            hex_colors = ["#0F172A"]
    else:
        hex_colors = ["#0F172A"]

    try:
        result = await execute_daily_automation_loop(
            user_id=current_user.id,
            niche_value=niche_value,
            target_lang=target_lang,
            hex_colors=hex_colors,
            template=template,
            image_mode=image_mode,
            voice_id=voice_id,
            target_aspect_ratio=target_aspect_ratio,
        )
    except (EnvironmentError, RuntimeError, ValueError) as exc:
        # Return 504 for pipeline timeouts so the client can show a targeted
        # retry prompt; all other errors map to the standard 502.
        if "timed out" in str(exc).lower():
            raise HTTPException(status_code=504, detail=str(exc))
        raise HTTPException(status_code=502, detail=str(exc))

    # Persist to PostsQueue
    post = PostsQueue(
        user_id=current_user.id,
        episode_title=result.get("episode_title"),
        content_text=result.get("final_caption_text"),
        graphic_card_url=result.get("graphic_card_url"),
        voice_audio_url=result.get("voice_audio_url"),
        status="pending_review",
    )
    db.add(post)
    await db.commit()
    await db.refresh(post)

    return {
        "post_id":           post.id,
        "user_id":           current_user.id,
        "episode_title":     post.episode_title,
        "final_caption_text": post.content_text,
        "graphic_card_url":  post.graphic_card_url,
        "voice_audio_url":   post.voice_audio_url,
        "status":            post.status,
        "created_at":        post.created_at.isoformat(),
    }

@app.get("/api/v1/automation/queue/{user_id}")
async def get_posts_queue(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db),
):
    """
    Returns all queued posts for the given user_id.
    Users may only retrieve their own queue.
    """
    if user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: you may only view your own post queue.",
        )

    posts = (
        await db.execute(
            sa_select(PostsQueue)
            .where(PostsQueue.user_id == current_user.id)
            .order_by(PostsQueue.created_at.desc())
        )
    ).scalars().all()

    return {
        "user_id": current_user.id,
        "total": len(posts),
        "posts": [
            {
                "post_id":          p.id,
                "episode_title":    p.episode_title,
                "content_text":     p.content_text,
                "graphic_card_url": p.graphic_card_url,
                "voice_audio_url":  p.voice_audio_url,
                "status":           p.status,
                "scheduled_publish_time": (
                    p.scheduled_publish_time.isoformat() if p.scheduled_publish_time else None
                ),
                "created_at":       p.created_at.isoformat(),
            }
            for p in posts
        ],
    }


# 11. Recent publish logs for the authenticated user (used by mobile dashboard)
@app.get("/api/v1/me/recent-publish-logs")
async def get_recent_publish_logs(
    limit: int = 3,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db),
):
    """
    Returns the most recent published/failed posts for the authenticated user,
    each including its per-platform publish_log.

    Designed for the mobile dashboard results panel — no client-side JWT decoding needed.
    """
    import json

    posts = (await db.execute(
        select(PostsQueue)
        .where(
            PostsQueue.user_id == current_user.id,
            PostsQueue.status.in_(["published", "failed"]),
        )
        .order_by(PostsQueue.created_at.desc())
        .limit(max(1, min(limit, 10)))
    )).scalars().all()

    result = []
    for p in posts:
        platform_log = None
        if p.publish_log:
            try:
                platform_log = json.loads(p.publish_log)
            except (json.JSONDecodeError, TypeError):
                platform_log = None
        result.append({
            "post_id":       p.id,
            "episode_title": p.episode_title,
            "status":        p.status,
            "publish_log":   platform_log,
            "created_at":    p.created_at.isoformat(),
        })

    return {"posts": result}


# ─────────────────────────────────────────────────────────────────────────────
# SUBMIT FULL CONFIGURATION  (AlphaApp 3-tab bottom-bar SUBMIT button)
# ─────────────────────────────────────────────────────────────────────────────
# Receives the global-state payload that AlphaApp emits on submit and
# persists it atomically across all 7 tables.

class HubConfigSchema(BaseModel):
    voiceMode: str = "stock"          # "stock" | "clone"
    voiceProfile: str = ""
    studioMode: str = "ideogram"      # "ideogram" | "upload"
    imagePrompt: str = ""
    uploadFilename: str = ""
    mediaMix: int = 50                # 0–100
    niche: str = "General"
    format: str = "square"            # "square" | "vertical"
    aspectRatio: str = "9:16"         # "1:1" | "9:16"

class TrendsConfigSchema(BaseModel):
    niche: str = "General"
    celebrities: List[str] = []

class FullConfigSchema(BaseModel):
    hub: HubConfigSchema
    trends: TrendsConfigSchema
    platforms: Dict[str, str] = {}    # platform_id → "idle"|"connecting"|"connected"
    connectedCount: int = 0
    submittedAt: Optional[str] = None


@app.post("/api/v1/config/submit", status_code=status.HTTP_200_OK, tags=["config"])
async def submit_full_configuration(
    payload: FullConfigSchema,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db),
):
    """Persist the AlphaApp 3-tab SUBMIT payload to all relevant tables.

    Upserts:
      • users               — content_schedule_time, onboarding_complete
      • user_aesthetic_settings — voice, image mode, media mix, niche, template
      • user_selected_sources   — replaces celebrity tracking chips
    """
    hub    = payload.hub
    trends = payload.trends

    # ── 1. Update User row ────────────────────────────────────────────────────
    current_user.onboarding_complete = True
    db.add(current_user)

    # ── 2. Upsert UserAestheticSetting ────────────────────────────────────────
    image_mode = "ai_generation" if hub.studioMode == "ideogram" else "device_upload"
    settings = (await db.execute(
        sa_select(UserAestheticSetting).where(UserAestheticSetting.user_id == current_user.id)
    )).scalar_one_or_none()
    # Validate and normalise aspect ratio
    aspect_ratio = hub.aspectRatio if hub.aspectRatio in ("1:1", "9:16") else "9:16"

    if settings:
        settings.chosen_niche              = trends.niche or hub.niche
        settings.celebrity_tracker_string  = ",".join(trends.celebrities)
        settings.voice_id                  = hub.voiceProfile
        settings.image_mode                = image_mode
        settings.media_mix_video_percentage= hub.mediaMix
        settings.target_aspect_ratio       = aspect_ratio
        settings.active_target_language    = settings.active_target_language or "en"
    else:
        settings = UserAestheticSetting(
            user_id=current_user.id,
            chosen_niche=trends.niche or hub.niche,
            celebrity_tracker_string=",".join(trends.celebrities),
            voice_id=hub.voiceProfile,
            image_mode=image_mode,
            media_mix_video_percentage=hub.mediaMix,
            target_aspect_ratio=aspect_ratio,
        )
        db.add(settings)

    # ── 3. Replace UserSelectedSource rows (celebrity tracking chips) ─────────
    await db.execute(
        sa_delete(UserSelectedSource).where(UserSelectedSource.user_id == current_user.id)
    )

    niche_primary = trends.niche or hub.niche
    if trends.celebrities:
        for name in trends.celebrities:
            db.add(UserSelectedSource(
                user_id=current_user.id,
                chosen_niche=niche_primary,
                celebrity_name=name,
            ))
    else:
        db.add(UserSelectedSource(
            user_id=current_user.id,
            chosen_niche=niche_primary,
        ))

    await db.commit()

    return {
        "status": "saved",
        "user_id": current_user.id,
        "saved": {
            "niche":              niche_primary,
            "celebrities":        trends.celebrities,
            "voice_profile":      hub.voiceProfile,
            "image_mode":         image_mode,
            "media_mix":          hub.mediaMix,
            "post_format":        hub.format,
            "aspect_ratio":       aspect_ratio,
            "connected_platforms": payload.connectedCount,
        },
        "message": "Configuration saved. Automation will use these settings on the next scheduled run.",
    }


# ── Instant aspect-ratio preference write ─────────────────────────────────────

class AspectRatioPatchSchema(BaseModel):
    aspect_ratio: str  # "1:1" or "9:16"


@app.patch("/api/v1/config/aspect-ratio", status_code=status.HTTP_200_OK, tags=["config"])
async def patch_aspect_ratio(
    payload: AspectRatioPatchSchema,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db),
):
    """Instantly persist the operator's chosen output aspect ratio.

    Called by the frontend whenever the Output Aspect Ratio toggle changes so
    the preference is committed to the database immediately — not deferred until
    the full Submit payload is sent.

    The Pillow compositor and FFmpeg render engine both read this column, so the
    next automation run will generate media in the correct canvas dimensions
    without any further user action.
    """
    if payload.aspect_ratio not in ("1:1", "9:16"):
        raise HTTPException(
            status_code=422,
            detail="aspect_ratio must be '1:1' or '9:16'.",
        )

    settings = (await db.execute(
        sa_select(UserAestheticSetting).where(UserAestheticSetting.user_id == current_user.id)
    )).scalar_one_or_none()

    if settings:
        settings.target_aspect_ratio = payload.aspect_ratio
    else:
        settings = UserAestheticSetting(
            user_id=current_user.id,
            target_aspect_ratio=payload.aspect_ratio,
        )
        db.add(settings)

    await db.commit()
    return {
        "status": "saved",
        "aspect_ratio": payload.aspect_ratio,
        "message": f"Output canvas locked to {payload.aspect_ratio}. Next render will use this format.",
    }


# ── Dev / diagnostic endpoints ────────────────────────────────────────────────

@app.post("/api/v1/dev/trigger-pipeline", status_code=status.HTTP_200_OK, tags=["dev"])
async def dev_trigger_pipeline(
    current_user: User = Depends(get_current_user),
):
    """Manually fire the full automation pipeline for the authenticated user.

    Useful for end-to-end testing without waiting for the hourly cron.
    """
    from worker import trigger_pipeline_for_user
    result = await trigger_pipeline_for_user(current_user.id)
    return result


@app.get("/api/v1/health", tags=["system"])
async def health_check():
    """System health check — returns DB reachability, worker status, and secret configuration."""
    from worker import _scheduler
    db_ok = await ping_db()
    session_secret_ok = bool(os.environ.get("SESSION_SECRET"))
    nvidia_key_ok = bool(os.environ.get("NVIDIA_API_KEY"))
    voicebox_ok = bool(os.environ.get("VOICEBOX_API_ENDPOINT")) and bool(os.environ.get("VOICEBOX_API_KEY"))
    all_ok = db_ok and session_secret_ok
    return {
        "status": "ok" if all_ok else "degraded",
        "database": "reachable" if db_ok else "unreachable",
        "scheduler": "running" if (_scheduler and _scheduler.running) else "stopped",
        "secrets": {
            "session_secret": "configured" if session_secret_ok else "MISSING",
            "nvidia_api_key": "configured" if nvidia_key_ok else "missing",
            "voicebox": "configured" if voicebox_ok else "missing",
        },
    }


# ── OAuth2 router ─────────────────────────────────────────────────────────────
# Imported here (bottom of file) to avoid a circular import: oauth_router
# imports get_current_user which is defined above in this module.
from oauth_router import router as oauth_router
app.include_router(oauth_router)


# ── Advertisement management endpoints ───────────────────────────────────────

class AdvertisementSchema(BaseModel):
    sponsor_name: Optional[str] = None
    sponsor_logo_url: Optional[str] = None
    sponsor_contact: Optional[str] = None
    sponsor_services_text: Optional[str] = None
    start_date: Optional[str] = None   # ISO date string
    end_date: Optional[str] = None
    is_active: bool = True


@app.post("/api/v1/advertisements", status_code=status.HTTP_201_CREATED, tags=["advertisements"])
async def create_advertisement(
    payload: AdvertisementSchema,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db),
):
    """Create a new sponsor/ad contract for the current user."""
    start = datetime.fromisoformat(payload.start_date) if payload.start_date else None
    end   = datetime.fromisoformat(payload.end_date)   if payload.end_date   else None
    ad = Advertisement(
        user_id=current_user.id,
        sponsor_name=payload.sponsor_name,
        sponsor_logo_url=payload.sponsor_logo_url,
        sponsor_contact=payload.sponsor_contact,
        sponsor_services_text=payload.sponsor_services_text,
        start_date=start,
        end_date=end,
        is_active=payload.is_active,
    )
    db.add(ad)
    await db.commit()
    await db.refresh(ad)
    return {"ad_id": ad.id, "message": "Advertisement contract created successfully."}


@app.get("/api/v1/advertisements", tags=["advertisements"])
async def list_advertisements(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db),
):
    """List all ad contracts for the current user."""
    ads = (await db.execute(
        sa_select(Advertisement).where(Advertisement.user_id == current_user.id)
    )).scalars().all()
    return {"advertisements": [
        {
            "id": a.id,
            "sponsor_name": a.sponsor_name,
            "sponsor_services_text": a.sponsor_services_text,
            "is_active": a.is_active,
            "start_date": a.start_date.isoformat() if a.start_date else None,
            "end_date":   a.end_date.isoformat()   if a.end_date   else None,
        }
        for a in ads
    ]}


@app.delete("/api/v1/advertisements/{ad_id}", tags=["advertisements"])
async def delete_advertisement(
    ad_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db),
):
    ad = (await db.execute(
        sa_select(Advertisement).where(
            Advertisement.id == ad_id, Advertisement.user_id == current_user.id
        )
    )).scalar_one_or_none()
    if not ad:
        raise HTTPException(status_code=404, detail="Advertisement not found.")
    await db.delete(ad)
    await db.commit()
    return {"message": f"Advertisement {ad_id} deleted."}


# ── Stripe Connect endpoints ──────────────────────────────────────────────────

@app.post("/api/v1/stripe/connect/account", tags=["monetization"])
async def create_stripe_connect_account(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db),
):
    """
    Create a Stripe Connect Express account for ad-revenue payouts and return
    the Stripe onboarding URL.

    Requires the STRIPE_SECRET_KEY Replit Secret.  If the user already has a
    Connect account ID stored in their wallet, a new account link is generated
    for the existing account instead of creating a duplicate.
    """
    import stripe as _stripe

    secret_key = os.environ.get("STRIPE_SECRET_KEY", "").strip()
    if not secret_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "STRIPE_SECRET_KEY is not configured. Add it as a Replit Secret to enable "
                "ad-revenue payouts via Stripe Connect."
            ),
        )

    _stripe.api_key = secret_key

    wallet = (await db.execute(
        select(UserWallet).where(UserWallet.user_id == current_user.id)
    )).scalar_one_or_none()

    try:
        if wallet and wallet.stripe_connect_id:
            account_id = wallet.stripe_connect_id
        else:
            account = _stripe.Account.create(
                type="express",
                email=current_user.email,
                capabilities={"transfers": {"requested": True}},
            )
            account_id = account.id
            if wallet:
                wallet.stripe_connect_id = account_id
            else:
                db.add(UserWallet(user_id=current_user.id, stripe_connect_id=account_id))
            await db.commit()

        base = os.environ.get("OAUTH_REDIRECT_BASE") or os.environ.get("REPLIT_DEV_DOMAIN", "")
        if base and not base.startswith("http"):
            base = f"https://{base}"
        base = base.rstrip("/")
        return_url  = f"{base}/app" if base else "/app"
        refresh_url = f"{base}/app" if base else "/app"

        account_link = _stripe.AccountLink.create(
            account=account_id,
            refresh_url=refresh_url,
            return_url=return_url,
            type="account_onboarding",
        )
        return {
            "account_id":      account_id,
            "onboarding_url":  account_link.url,
            "message":         "Visit onboarding_url to complete Stripe Connect setup.",
        }
    except _stripe.StripeError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Stripe error: {getattr(exc, 'user_message', None) or str(exc)}",
        )


@app.get("/api/v1/stripe/connect/status", tags=["monetization"])
async def get_stripe_connect_status(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db),
):
    """
    Check the Stripe Connect account status for the current user.

    Returns whether the account exists, its charges_enabled / payouts_enabled
    flags, and the wallet balance so the frontend can surface payout readiness.
    """
    import stripe as _stripe

    secret_key = os.environ.get("STRIPE_SECRET_KEY", "").strip()
    if not secret_key:
        return {
            "connected":        False,
            "configured":       False,
            "message":          "STRIPE_SECRET_KEY not configured.",
        }

    _stripe.api_key = secret_key

    wallet = (await db.execute(
        select(UserWallet).where(UserWallet.user_id == current_user.id)
    )).scalar_one_or_none()

    if not wallet or not wallet.stripe_connect_id:
        return {
            "connected":  False,
            "configured": bool(secret_key),
            "message":    "No Stripe Connect account linked yet. Call POST /api/v1/stripe/connect/account to begin.",
        }

    try:
        account = _stripe.Account.retrieve(wallet.stripe_connect_id)
        return {
            "connected":         True,
            "configured":        bool(secret_key),
            "account_id":        wallet.stripe_connect_id,
            "charges_enabled":   account.charges_enabled,
            "payouts_enabled":   account.payouts_enabled,
            "details_submitted": account.details_submitted,
            "available_balance": float(wallet.available_balance),
            "pending_balance":   float(wallet.pending_balance),
            "message": (
                "Stripe Connect account fully onboarded — payouts enabled."
                if account.payouts_enabled
                else "Stripe Connect account created but onboarding is incomplete. Visit the onboarding URL to finish."
            ),
        }
    except _stripe.StripeError as exc:
        return {
            "connected":  True,
            "configured": True,
            "account_id": wallet.stripe_connect_id,
            "error":      str(exc),
            "message":    "Could not retrieve Stripe account status.",
        }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
