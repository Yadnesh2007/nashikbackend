"""Certified Judicial Evidence Export Package Routes."""

import io
import json
import uuid
import zipfile
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...core.database import get_db
from ...core.security import SessionUser, get_current_user
from ...models.entities import DocumentVersion, Case
from ...services.retrieval import retrieval_service
from ...services.readiness import readiness_service
from ...services.audit import audit_service
from ...services.anchoring import anchoring_service
from evidenceshield_crypto import generate_evidence_passport

router = APIRouter(prefix="", tags=["Judicial Exports"])


@router.post("/cases/{id}/exports")
async def generate_judicial_export(
    id: str,
    db: AsyncSession = Depends(get_db),
    user: SessionUser = Depends(get_current_user),
):
    # Invariant: Export requires fresh MFA within 10 minutes
    if not user.is_mfa_fresh:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Generating certified export package requires fresh MFA verification.",
        )

    # Invariant: Only Prosecutor can generate certified export
    if user.role != "PROSECUTOR":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only Public Prosecutors may generate certified judicial export packages.",
        )

    # Preflight readiness check
    readiness = await readiness_service.evaluate_case_readiness(db, id)
    if not readiness["is_ready"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Case is not ready for export due to omissions: {'; '.join(readiness['omissions'])}",
        )

    export_id = str(uuid.uuid4())

    await audit_service.append_event(
        session=db,
        event_type="JUDICIAL_EXPORT_GENERATED",
        actor_id=user.user_id,
        actor_role=user.role,
        actor_agency=user.agency,
        resource_type="case_export",
        resource_id=export_id,
        payload={"case_id": id},
    )
    await db.commit()

    return {
        "export_id": export_id,
        "case_id": id,
        "download_url": f"/api/v1/cases/{id}/exports/{export_id}/bundle",
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        "readiness": readiness,
    }
