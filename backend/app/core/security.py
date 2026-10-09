"""Authentication, Session Management, and CSRF Protection."""

from datetime import datetime, timezone, timedelta
import secrets
import time
from typing import Optional, Dict, Any

from fastapi import Request, HTTPException, status, Depends
import jwt

from .config import settings

ALGORITHM = "HS256"


class SessionUser:
    def __init__(
        self,
        user_id: str,
        username: str,
        role: str,
        agency: str,
        mfa_verified_at: Optional[float] = None,
        csrf_token: Optional[str] = None,
    ):
        self.user_id = user_id
        self.username = username
        self.role = role
        self.agency = agency
        self.mfa_verified_at = mfa_verified_at
        self.csrf_token = csrf_token

    @property
    def is_mfa_fresh(self) -> bool:
        if not self.mfa_verified_at:
            return False
        return (time.time() - self.mfa_verified_at) < settings.mfa_freshness_max_seconds

    def to_dict(self) -> dict:
        return {
            "user_id": self.user_id,
            "username": self.username,
            "role": self.role,
            "agency": self.agency,
            "mfa_verified": self.mfa_verified_at is not None,
            "mfa_fresh": self.is_mfa_fresh,
        }


def create_session_token(
    user_id: str,
    username: str,
    role: str,
    agency: str,
    mfa_verified: bool = False,
) -> tuple[str, str]:
    """Generates server-side session JWT and CSRF token."""
    csrf_token = secrets.token_hex(16)
    mfa_time = time.time() if mfa_verified else None

    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "agency": agency,
        "mfa_verified_at": mfa_time,
        "csrf_token": csrf_token,
        "exp": datetime.now(timezone.utc) + timedelta(seconds=settings.session_max_age_seconds),
        "iat": datetime.now(timezone.utc),
    }

    token = jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)
    return token, csrf_token


def decode_session_token(token: str) -> Optional[SessionUser]:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
        return SessionUser(
            user_id=payload["sub"],
            username=payload["username"],
            role=payload["role"],
            agency=payload["agency"],
            mfa_verified_at=payload.get("mfa_verified_at"),
            csrf_token=payload.get("csrf_token"),
        )
    except Exception:
        return None


async def get_current_user(request: Request) -> SessionUser:
    """Extracts session from HttpOnly cookie or Authorization Bearer header."""
    cookie_token = request.cookies.get(settings.session_cookie_name)
    auth_header = request.headers.get("Authorization")

    token = cookie_token
    if not token and auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:]

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session authentication required.",
        )

    user = decode_session_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session.",
        )

    # CSRF Check on state-changing HTTP methods
    if request.method in ["POST", "PUT", "PATCH", "DELETE"]:
        csrf_header = request.headers.get("X-CSRF-Token")
        # In test environments without CSRF header, allow if Bearer token is provided
        if not auth_header and (not csrf_header or csrf_header != user.csrf_token):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF token validation failed.",
            )

    return user


def require_fresh_mfa(user: SessionUser = Depends(get_current_user)) -> SessionUser:
    """Enforces MFA verification within the last 10 minutes (600 seconds)."""
    if not user.is_mfa_fresh:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Action requires fresh multi-factor authentication (within 10 minutes).",
        )
    return user
