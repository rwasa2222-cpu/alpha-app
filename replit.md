# ALPHA Automated Visual Podcast Factory — API

A FastAPI backend that powers the ALPHA mobile app: an automated visual podcast factory with multi-platform social media distribution.

## Stack

- **Runtime**: Python 3.11
- **Framework**: FastAPI + Uvicorn
- **Database**: SQLite via SQLAlchemy (file: `alpha.db`)
- **Auth**: bcrypt password hashing + TOTP 2FA (pyotp)
- **Image generation**: Pillow (local compositing)

## How to run

The workflow `Start application` runs the server:

```
python main.py
```

Starts Uvicorn on **port 8000** with hot-reload. Interactive API docs available at `/docs`.

## Project structure

| File | Purpose |
|---|---|
| `main.py` | FastAPI app — auth & onboarding endpoints |
| `models.py` | SQLAlchemy models + DB init (`PostsQueue`, `UserWallet`, `UserAestheticSetting`) |
| `tasks.py` | Background task logic — scraping, AI writing, Pillow image compositing |
| `distribution.py` | Multi-platform publishing engine + Stripe wallet ledger |

## API endpoints

| Method | Path | Description |
|---|---|---|
| POST | `/api/v1/auth/register` | Register user, returns 2FA TOTP seed |
| POST | `/api/v1/onboarding/niche-dropdown` | Save niche/celebrity tracking preference |
| POST | `/api/v1/onboarding/series-setup` | Configure daily automation schedule |
| POST | `/api/v1/onboarding/voice-studio` | Set up voice clone or stock voice |
| POST | `/api/v1/onboarding/image-studio` | Configure image source (upload or AI gen) |

## External services (not yet wired up)

These are referenced in the code but need API keys/credentials to be functional:

- **NVIDIA Nemotron** — AI script writing & translation
- **Voicebox** — Voice cloning & synthesis (see path conventions below)
- **Ideogram / Easy Diffusion** — AI image generation
- **Stripe Connect** — Ad revenue payouts
- **Social platform APIs** — YouTube, Instagram, TikTok, Facebook, LinkedIn, Threads, WhatsApp

## Voicebox provider & path conventions

The app expects the Voicebox provider to expose these three REST paths beneath `VOICEBOX_API_ENDPOINT`:

| Path | Method | Used by |
|---|---|---|
| `/health` | GET | Startup health check — confirms the provider is reachable |
| `/tts` | POST | `synthesize_voice_audio()` in `tasks.py` — generates MP3 audio from text |
| `/clone` | POST | `setup_voicebox_profile()` in `main.py` — uploads a 45-second voice sample |
| `/voices/select` | POST | `setup_voicebox_profile()` in `main.py` — registers a stock voice selection |

All authenticated calls send `Authorization: Bearer <VOICEBOX_API_KEY>`.

**If your provider uses different paths**, update `VOICEBOX_API_ENDPOINT` so it includes any shared path prefix (e.g. `https://api.myprovider.com/v2`) and verify the four paths above resolve correctly. The startup health check will warn in logs if `/health` is unreachable or returns an error status; the `/tts` and `/clone` endpoints will return HTTP 503 with an actionable message if the provider returns 404 or 405.

## User preferences

- This is a mobile app backend — keep it as a REST API, not a web frontend.
