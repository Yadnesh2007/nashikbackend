"""Custody Transfer Management, Platform Receipts, and Gap Rules."""

from datetime import datetime, timezone
import json
import uuid
from typing import Optional, Dict, Any, List

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from evidenceshield_crypto import sign_canonical_payload
from ..models.entities import CustodyTransfer, DocumentVersion, CaseAssignment
from .audit import audit_service, PLATFORM_PRIV_KEY
from ..core.security import SessionUser


class CustodyService:
    """Manages legal chain of custody handoffs and deterministic gap detection."""

    async def initiate_transfer(
        self,
        session: AsyncSession,
        version_id: str,
        user: SessionUser,
        recipient_id: str,
        recipient_agency: str,
        reason: str,
    ) -> CustodyTransfer:
        # 1. Fetch version and check state
        v_stmt = select(DocumentVersion).where(DocumentVersion.version_id == version_id)
        v_res = await session.execute(v_stmt)
        version = v_res.scalar_one_or_none()

        if not version:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Version not found.")

        # Invariant: Transfers require confirmed anchoring
        if version.state != "VERIFIED_ANCHORED":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot transfer version in state '{version.state}'. Must be 'VERIFIED_ANCHORED'.",
            )

        # Invariant: One pending transfer per version
        p_stmt = (
            select(CustodyTransfer)
            .where(CustodyTransfer.version_id == version_id)
            .where(CustodyTransfer.state == "PENDING")
        )
        p_res = await session.execute(p_stmt)
        if p_res.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A pending custody transfer already exists for this evidence version.",
            )

        transfer_id = str(uuid.uuid4())
        now_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        # Platform-signed dispatch receipt
        dispatch_receipt = {
            "transfer_id": transfer_id,
            "version_id": version_id,
            "digest": version.digest,
            "sender_id": user.user_id,
            "sender_agency": user.agency,
            "recipient_id": recipient_id,
            "recipient_agency": recipient_agency,
            "timestamp": now_utc,
            "type": "CUSTODY_DISPATCH",
        }
        sender_sig, _ = sign_canonical_payload(dispatch_receipt, PLATFORM_PRIV_KEY)

        transfer = CustodyTransfer(
            transfer_id=transfer_id,
            version_id=version_id,
            case_id=version.case_id,
            sender_id=user.user_id,
            sender_agency=user.agency,
            recipient_id=recipient_id,
            recipient_agency=recipient_agency,
            reason=reason,
            state="PENDING",
            initiated_at=datetime.now(timezone.utc),
            sender_receipt_sig=sender_sig,
        )
        session.add(transfer)

        await audit_service.append_event(
            session=session,
            event_type="CUSTODY_TRANSFER_INITIATED",
            actor_id=user.user_id,
            actor_role=user.role,
            actor_agency=user.agency,
            resource_type="custody_transfer",
            resource_id=transfer_id,
            payload=dispatch_receipt,
        )

        await session.flush()
        return transfer

    async def accept_transfer(
        self,
        session: AsyncSession,
        transfer_id: str,
        user: SessionUser,
        notes: Optional[str] = None,
    ) -> CustodyTransfer:
        stmt = select(CustodyTransfer).where(CustodyTransfer.transfer_id == transfer_id)
        res = await session.execute(stmt)
        transfer = res.scalar_one_or_none()

        if not transfer:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Transfer not found.")

        # Idempotent check
        if transfer.state == "ACCEPTED":
            return transfer

        if transfer.state != "PENDING":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Transfer cannot be accepted in state '{transfer.state}'.",
            )

        # Invariant: Only designated recipient or matching agency can accept
        if user.user_id != transfer.recipient_id and user.agency != transfer.recipient_agency:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only the designated recipient or recipient agency can accept this custody handoff.",
            )

        now_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        acceptance_receipt = {
            "transfer_id": transfer_id,
            "version_id": transfer.version_id,
            "accepted_by": user.user_id,
            "agency": user.agency,
            "timestamp": now_utc,
            "type": "CUSTODY_ACCEPTANCE",
        }
        recipient_sig, _ = sign_canonical_payload(acceptance_receipt, PLATFORM_PRIV_KEY)

        transfer.state = "ACCEPTED"
        transfer.responded_at = datetime.now(timezone.utc)
        transfer.response_notes = notes
        transfer.recipient_receipt_sig = recipient_sig

        await audit_service.append_event(
            session=session,
            event_type="CUSTODY_TRANSFER_ACCEPTED",
            actor_id=user.user_id,
            actor_role=user.role,
            actor_agency=user.agency,
            resource_type="custody_transfer",
            resource_id=transfer_id,
            payload=acceptance_receipt,
        )

        await session.flush()
        return transfer

    async def reject_transfer(
        self,
        session: AsyncSession,
        transfer_id: str,
        user: SessionUser,
        reason: str,
    ) -> CustodyTransfer:
        stmt = select(CustodyTransfer).where(CustodyTransfer.transfer_id == transfer_id)
        res = await session.execute(stmt)
        transfer = res.scalar_one_or_none()

        if not transfer:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Transfer not found.")

        if transfer.state == "REJECTED":
            return transfer

        if transfer.state != "PENDING":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Transfer is not pending.")

        if user.user_id != transfer.recipient_id and user.agency != transfer.recipient_agency:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only recipient can reject handoff.")

        transfer.state = "REJECTED"
        transfer.responded_at = datetime.now(timezone.utc)
        transfer.response_notes = reason

        await audit_service.append_event(
            session=session,
            event_type="CUSTODY_TRANSFER_REJECTED",
            actor_id=user.user_id,
            actor_role=user.role,
            actor_agency=user.agency,
            resource_type="custody_transfer",
            resource_id=transfer_id,
            payload={"reason": reason},
        )

        await session.flush()
        return transfer

    async def detect_custody_gaps(
        self,
        session: AsyncSession,
        case_id: str,
    ) -> List[Dict[str, Any]]:
        """Evaluates deterministic gap rules across transfers for a case."""
        stmt = (
            select(CustodyTransfer)
            .where(CustodyTransfer.case_id == case_id)
            .order_by(CustodyTransfer.initiated_at.asc())
        )
        res = await session.execute(stmt)
        transfers = res.scalars().all()

        gaps = []
        for t in transfers:
            if t.state == "PENDING":
                gaps.append({
                    "transfer_id": t.transfer_id,
                    "version_id": t.version_id,
                    "gap_type": "MISSING_ACKNOWLEDGMENT",
                    "description": f"Transfer from {t.sender_agency} to {t.recipient_agency} has not been acknowledged by {t.recipient_id}.",
                    "next_action": f"Recipient ({t.recipient_id}) must accept or reject transfer.",
                })
        return gaps


custody_service = CustodyService()
