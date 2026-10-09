"""EvidenceShield AI - FastAPI Main Application Entrypoint."""

from datetime import datetime, timezone
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from .core.config import settings
from .core.database import init_db
from .api.v1.auth import router as auth_router
from .api.v1.cases import router as cases_router
from .api.v1.versions import router as versions_router
from .api.v1.transfers import router as transfers_router
from .api.v1.alerts import router as alerts_router
from .api.v1.analysis import router as analysis_router
from .api.v1.exports import router as exports_router
from .api.v1.audit import router as audit_router

app = FastAPI(
    title="EvidenceShield AI API",
    description="Tamper-Evident Zero-Trust Judicial & Forensic Document Management System",
    version="1.0.0-s2",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def on_startup():
    await init_db()


# Global RFC 7807 Error Envelope Handlers
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    now_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    code = "ERROR"
    if exc.status_code == 401:
        code = "UNAUTHORIZED"
    elif exc.status_code == 403:
        code = "FORBIDDEN"
    elif exc.status_code == 404:
        code = "NOT_FOUND"
    elif exc.status_code == 422:
        code = "UNPROCESSABLE_ENTITY"

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "type": f"https://evidenceshield.local/errors/{code}",
            "title": exc.detail if isinstance(exc.detail, str) else "HTTP Error",
            "status": exc.status_code,
            "detail": exc.detail if isinstance(exc.detail, str) else str(exc.detail),
            "instance": request.url.path,
            "code": code,
            "timestamp": now_utc,
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    now_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "type": "https://evidenceshield.local/errors/VALIDATION_ERROR",
            "title": "Request Validation Error",
            "status": 422,
            "detail": str(exc.errors()),
            "instance": request.url.path,
            "code": "VALIDATION_ERROR",
            "timestamp": now_utc,
        },
    )


# Health check endpoint
@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "evidenceshield-backend",
        "version": "1.0.0-s2",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# Include /api/v1 routes
app.include_router(auth_router, prefix=settings.api_prefix)
app.include_router(cases_router, prefix=settings.api_prefix)
app.include_router(versions_router, prefix=settings.api_prefix)
app.include_router(transfers_router, prefix=settings.api_prefix)
app.include_router(alerts_router, prefix=settings.api_prefix)
app.include_router(analysis_router, prefix=settings.api_prefix)
app.include_router(exports_router, prefix=settings.api_prefix)
app.include_router(audit_router, prefix=settings.api_prefix)
