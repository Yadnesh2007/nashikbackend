"""Integrity Alerts and Review API Routes."""

from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...core.database import get_db
from ...core.security import SessionUser, get_current_user
from ...models.entities import IntegrityAlert
from ...services.audit import audit_service

router = APIRouter(prefix="", tags=["Integrity Alerts"])


class AlertReviewRequest(BaseModel):
    status: str  # CONFIRMED_TAMPERED or DISMISSED_FALSE_POSITIVE
    disposition_notes: str


@router.get("/cases/{id}/alerts")
async def list_case_alerts(
    id: str,
    db: AsyncSession = Depends(get_db),
    user: SessionUser = Depends(get_current_user),
):
    stmt = (
        select(IntegrityAlert)
        .where(IntegrityAlert.case_id == id)
        .order_by(IntegrityAlert.created_at.desc())
    )
    res = await db.execute(stmt)
    alerts = res.scalars().all()

    return [
        {
            "alert_id": a.alert_id,
            "version_id": a.version_id,
            "case_id": a.case_id,
            "alert_type": a.alert_type,
            "failure_stage": a.failure_stage,
            "error_details": a.error_details,
            "status": a.status,
            "assigned_reviewer_id": a.assigned_reviewer_id,
            "disposition_notes": a.disposition_notes,
            "created_at": a.created_at,
            "resolved_at": a.resolved_at,
        }
        for a in alerts
    ]


@router.post("/alerts/{id}/review")
async def review_alert(
    id: str,
    req: AlertReviewRequest,
    db: AsyncSession = Depends(get_db),
    user: SessionUser = Depends(get_current_user),
):
    stmt = select(IntegrityAlert).where(IntegrityAlert.alert_id == id)
    res = await db.execute(stmt)
    alert = res.scalar_one_or_none()

    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found.")

    if req.status not in ["CONFIRMED_TAMPERED", "DISMISSED_FALSE_POSITIVE"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Status must be CONFIRMED_TAMPERED or DISMISSED_FALSE_POSITIVE.",
        )

    alert.status = req.status
    alert.disposition_notes = req.disposition_notes
    alert.assigned_reviewer_id = user.user_id
    alert.resolved_at = datetime.now(timezone.utc)

    # Invariant: Dismissing alert does NOT un-quarantine evidence unless verification passes
    await audit_service.append_event(
        session=db,
        event_type="INTEGRITY_ALERT_REVIEWED",
        actor_id=user.user_id,
        actor_role=user.role,
        actor_agency=user.agency,
        resource_type="integrity_alert",
        resource_id=alert.alert_id,
        payload={"disposition": req.status, "notes": req.disposition_notes},
    )
    await db.commit()

    return {
        "alert_id": alert.alert_id,
        "version_id": alert.version_id,
        "case_id": alert.case_id,
        "status": alert.status,
        "disposition_notes": alert.disposition_notes,
        "resolved_at": alert.resolved_at,
    }
