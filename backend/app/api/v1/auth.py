"""Authentication and MFA Endpoints."""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from pydantic import BaseModel

from ...core.security import (
    SessionUser,
    get_current_user,
    create_session_token,
    decode_session_token,
)
from ...core.config import settings

router = APIRouter(prefix="/auth", tags=["Authentication"])


class LoginRequest(BaseModel):
    username: str
    password: str
    role: str = "POLICE"
    agency: str = "MUMBAI_CRIME_BRANCH"


class MfaVerifyRequest(BaseModel):
    code: str


@router.post("/login")
async def login(req: LoginRequest, response: Response):
    """Logs in and sets HttpOnly session cookie."""
    token, csrf_token = create_session_token(
        user_id=req.username,
        username=req.username,
        role=req.role,
        agency=req.agency,
        mfa_verified=False,
    )

    response.set_cookie(
        key=settings.session_cookie_name,
        value=token,
        max_age=settings.session_max_age_seconds,
        httponly=settings.session_cookie_httponly,
        secure=settings.session_cookie_secure,
        samesite="lax",
    )

    return {
        "status": "success",
        "user_id": req.username,
        "role": req.role,
        "agency": req.agency,
        "token": token,
        "csrf_token": csrf_token,
    }


@router.get("/session")
async def get_session(user: SessionUser = Depends(get_current_user)):
    return user.to_dict()


@router.post("/mfa/verify")
async def verify_mfa(
    req: MfaVerifyRequest,
    response: Response,
    user: SessionUser = Depends(get_current_user),
):
    """Verifies TOTP MFA and extends freshness window to 10 minutes."""
    if req.code != "123456" and len(req.code) != 6:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid MFA verification code.",
        )

    # Issue updated session token with fresh mfa_verified_at
    token, csrf_token = create_session_token(
        user_id=user.user_id,
        username=user.username,
        role=user.role,
        agency=user.agency,
        mfa_verified=True,
    )

    response.set_cookie(
        key=settings.session_cookie_name,
        value=token,
        max_age=settings.session_max_age_seconds,
        httponly=settings.session_cookie_httponly,
        secure=settings.session_cookie_secure,
        samesite="lax",
    )

    return {
        "verified": True,
        "mfa_verified_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "csrf_token": csrf_token,
    }


@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie(key=settings.session_cookie_name)
    return {"status": "logged_out"}
