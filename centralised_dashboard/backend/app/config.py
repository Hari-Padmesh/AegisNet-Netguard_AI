from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")


class Settings:
    mongo_uri = os.getenv("MONGODB_URI", "")
    mongo_database = os.getenv("MONGODB_DATABASE", "netguard_cloud")
    session_secret = os.getenv("SESSION_SECRET", "")
    frontend_origin = os.getenv("FRONTEND_ORIGIN", "http://localhost:5173").rstrip("/")
    public_api_url = os.getenv("PUBLIC_API_URL", "").rstrip("/")
    cookie_secure = os.getenv("COOKIE_SECURE", "false").lower() in {"1", "true", "yes"}
    cookie_samesite = os.getenv("COOKIE_SAMESITE", "lax").lower()
    session_days = 14


settings = Settings()
