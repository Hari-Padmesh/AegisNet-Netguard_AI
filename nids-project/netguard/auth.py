"""
netguard/auth.py
----------------
Authentication helpers for NetGuard dashboard and API routes.

Supports HTTP Basic (username/password) or Bearer API key via the
Authorization header. At least one method must be configured.
"""

from __future__ import annotations

import secrets
from typing import Optional

from netguard.config import NetGuardConfig


class AuthenticationError(Exception):
    """Raised when credentials are missing or invalid."""


def verify_api_key(provided: Optional[str], config: NetGuardConfig) -> bool:
    if not config.auth_api_key:
        return False
    if not provided:
        return False
    return secrets.compare_digest(provided, config.auth_api_key)


def verify_basic_auth(username: Optional[str], password: Optional[str], config: NetGuardConfig) -> bool:
    if not config.auth_username or not config.auth_password:
        return False
    if not username or not password:
        return False
    user_ok = secrets.compare_digest(username, config.auth_username)
    pass_ok = secrets.compare_digest(password, config.auth_password)
    return user_ok and pass_ok


def authenticate_request(
    authorization: Optional[str],
    config: NetGuardConfig,
) -> None:
    """
    Validate Authorization header against configured credentials.

    Accepts:
      - Bearer <api_key>
      - Basic <base64 user:pass>  (handled by FastAPI HTTPBasic in integration layer)

    Raises
    ------
    AuthenticationError
    """
    config.validate_auth()

    if not authorization:
        raise AuthenticationError("Missing Authorization header.")

    scheme, _, credential = authorization.partition(" ")
    scheme = scheme.lower()

    if scheme == "bearer" and verify_api_key(credential.strip(), config):
        return

    raise AuthenticationError("Invalid or unsupported credentials.")


def create_fastapi_auth_dependency(config: NetGuardConfig):
    """
    Return a FastAPI dependency that enforces NetGuard authentication.

    Usage (Phase 2 dashboard routes):
        require_auth = create_fastapi_auth_dependency(config)

        @router.get("/stats", dependencies=[Depends(require_auth)])
        ...
    """
    try:
        from fastapi import Depends, HTTPException, status
        from fastapi.security import HTTPAuthorizationCredentials, HTTPBasic, HTTPBasicCredentials, HTTPBearer
    except ImportError as exc:
        raise ImportError(
            "FastAPI is required for dashboard auth. Install with: pip install 'netguard[web]'"
        ) from exc

    basic = HTTPBasic(auto_error=False)
    bearer = HTTPBearer(auto_error=False)

    async def require_auth(
        basic_creds: Optional[HTTPBasicCredentials] = Depends(basic),
        bearer_creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
    ) -> str:
        config.validate_auth()

        if bearer_creds and verify_api_key(bearer_creds.credentials, config):
            return "api_key"

        if basic_creds and verify_basic_auth(basic_creds.username, basic_creds.password, config):
            return basic_creds.username

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid NetGuard credentials.",
            headers={"WWW-Authenticate": "Basic"},
        )

    return require_auth
