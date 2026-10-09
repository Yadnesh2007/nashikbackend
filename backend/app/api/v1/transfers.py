"""Custody Transfer API Routes."""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ...core.database import get_db
from ...core.security import SessionUser, get_current_user
from ...services.custody import custody_service

router = APIRouter(prefix="", tags=["Custody Transfers"])


class TransferCreateRequest(BaseModel):
    recipient_id: str
    recipient_agency: str
    reason: str


class TransferAcceptRequest(BaseModel):
    notes: Optional[str] = None


class TransferRejectRequest(BaseModel):
    reason: str


@router.post("/versions/{id}/transfers", status_code=status.HTTP_201_CREATED)
async def initiate_transfer(
    id: str,
    req: TransferCreateRequest,
    db: AsyncSession = Depends(get_db),
    user: SessionUser = Depends(get_current_user),
):
    transfer = await custody_service.initiate_transfer(
        session=db,
        version_id=id,
        user=user,
        recipient_id=req.recipient_id,
        recipient_agency=req.recipient_agency,
        reason=req.reason,
    )
    await db.commit()

    return {
        "transfer_id": transfer.transfer_id,
        "version_id": transfer.version_id,
        "case_id": transfer.case_id,
        "sender_id": transfer.sender_id,
        "sender_agency": transfer.sender_agency,
        "recipient_id": transfer.recipient_id,
        "recipient_agency": transfer.recipient_agency,
        "state": transfer.state,
        "reason": transfer.reason,
        "initiated_at": transfer.initiated_at,
        "sender_receipt_sig": transfer.sender_receipt_sig,
    }


@router.post("/transfers/{id}/accept")
async def accept_transfer(
    id: str,
    req: TransferAcceptRequest,
    db: AsyncSession = Depends(get_db),
    user: SessionUser = Depends(get_current_user),
):
    transfer = await custody_service.accept_transfer(
        session=db,
        transfer_id=id,
        user=user,
        notes=req.notes,
    )
    await db.commit()

    return {
        "transfer_id": transfer.transfer_id,
        "version_id": transfer.version_id,
        "case_id": transfer.case_id,
        "state": transfer.state,
        "recipient_id": transfer.recipient_id,
        "recipient_agency": transfer.recipient_agency,
        "responded_at": transfer.responded_at,
        "recipient_receipt_sig": transfer.recipient_receipt_sig,
    }


@router.post("/transfers/{id}/reject")
async def reject_transfer(
    id: str,
    req: TransferRejectRequest,
    db: AsyncSession = Depends(get_db),
    user: SessionUser = Depends(get_current_user),
):
    transfer = await custody_service.reject_transfer(
        session=db,
        transfer_id=id,
        user=user,
        reason=req.reason,
    )
    await db.commit()

    return {
        "transfer_id": transfer.transfer_id,
        "version_id": transfer.version_id,
        "case_id": transfer.case_id,
        "state": transfer.state,
        "responded_at": transfer.responded_at,
        "response_notes": transfer.response_notes,
    }
