from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from pwdlib import PasswordHash
from app.config import settings

password_hash = PasswordHash.recommended()
SESSION_COOKIE = "netguard_session"


def digest(value: str) -> str:
    """Hash a high-entropy project credential for storage."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def session_digest(value: str) -> str:
    """Key session token hashes so a database-only leak cannot validate tokens."""
    return hmac.new(settings.session_secret.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()


def new_session() -> tuple[str, datetime]:
    raw = secrets.token_urlsafe(40)
    expires = datetime.now(timezone.utc) + timedelta(days=14)
    return raw, expires


def new_ingest_key() -> str:
    return "ngk_" + secrets.token_urlsafe(36)
