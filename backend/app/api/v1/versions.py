"""Document Version, Content Retrieval, Verification, Passport, and Derivatives."""

import base64
import json
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...core.database import get_db
from ...core.security import SessionUser, get_current_user
from ...models.entities import DocumentVersion, AuditEvent, MerkleCheckpoint
from ...services.retrieval import retrieval_service
from ...services.integrity import integrity_service
from ...services.lineage import lineage_service
from ...services.anchoring import anchoring_service
from evidenceshield_crypto import generate_evidence_passport

router = APIRouter(prefix="", tags=["Versions & Verification"])


class DerivativeCreateRequest(BaseModel):
    operation: str
    tool_name: str
    tool_version: str
    file_name: str
    mime_type: str
    content_base64: str


@router.get("/versions/{id}")
async def get_version(
    id: str,
    db: AsyncSession = Depends(get_db),
    user: SessionUser = Depends(get_current_user),
):
    stmt = select(DocumentVersion).where(DocumentVersion.version_id == id)
    res = await db.execute(stmt)
    version = res.scalar_one_or_none()
    if not version:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Version not found.")

    return {
        "version_id": version.version_id,
        "document_id": version.document_id,
        "case_id": version.case_id,
        "version_number": version.version_number,
        "state": version.state,
        "digest": version.digest,
        "size_bytes": version.size_bytes,
        "mime_type": version.mime_type,
        "file_name": version.file_name,
        "page_count": version.page_count,
        "declared_capture_time": version.declared_capture_time,
        "declared_timezone": version.declared_timezone,
        "created_at": version.created_at,
        "sealed_at": version.sealed_at,
    }


@router.get("/versions/{id}/content")
async def get_version_content(
    id: str,
    db: AsyncSession = Depends(get_db),
    user: SessionUser = Depends(get_current_user),
):
    """Verified Decrypted Evidence Download.

    Re-authenticates AES-GCM tag, checks SHA-256 digest, checks state.
    Enforces no-store caching headers.
    """
    plaintext, version = await retrieval_service.retrieve_verified_content(db, id, user)
    await db.commit()

    return Response(
        content=plaintext,
        media_type=version.mime_type,
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "Pragma": "no-cache",
            "Content-Disposition": f'attachment; filename="{version.file_name}"',
        },
    )


@router.post("/versions/{id}/verify")
async def verify_version(
    id: str,
    db: AsyncSession = Depends(get_db),
    user: SessionUser = Depends(get_current_user),
):
    """Triggers explicit multi-stage cryptographic verification."""
    result = await integrity_service.verify_version_integrity(db, id)
    await db.commit()
    return result


@router.post("/versions/{id}/tamper")
async def simulate_tamper(
    id: str,
    db: AsyncSession = Depends(get_db),
    user: SessionUser = Depends(get_current_user),
):
    """Simulates 1-bit corruption in ciphertext to demonstrate zero-trust quarantine."""
    from ...services.storage import storage_service
    stmt = select(DocumentVersion).where(DocumentVersion.version_id == id)
    res = await db.execute(stmt)
    version = res.scalar_one_or_none()
    if not version:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Version not found.")

    ct = await storage_service.get_ciphertext(version.object_key)
    corrupted_ct = bytearray(ct)
    if len(corrupted_ct) > 0:
        corrupted_ct[0] ^= 0x01  # Flip 1 single bit in ciphertext
    await storage_service.put_ciphertext(version.object_key, bytes(corrupted_ct))

    # Trigger multi-stage verification to quarantine immediately
    result = await integrity_service.verify_version_integrity(db, id)
    await db.commit()
    return {
        "tampered": True,
        "detail": "Flipped bit 0 in ciphertext. Triggered multi-stage cryptographic detector.",
        "verification_result": result,
    }


@router.get("/versions/{id}/passport")
async def get_version_passport(
    id: str,
    db: AsyncSession = Depends(get_db),
    user: SessionUser = Depends(get_current_user),
):
    """Generates signed Evidence Passport with Merkle proof and blockchain anchor."""
    stmt = select(DocumentVersion).where(DocumentVersion.version_id == id)
    res = await db.execute(stmt)
    version = res.scalar_one_or_none()
    if not version:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Version not found.")

    # 1. Fetch Ingestion Audit Event
    audit_stmt = (
        select(AuditEvent)
        .where(AuditEvent.resource_id == id)
        .where(AuditEvent.event_type == "DOCUMENT_INGESTED")
        .limit(1)
    )
    audit_res = await db.execute(audit_stmt)
    audit_event = audit_res.scalar_one_or_none()

    if not audit_event:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit event for version not found.")

    # 2. Fetch Merkle Proof
    merkle_proof = await anchoring_service.get_inclusion_proof_for_event(db, audit_event.sequence_id)

    # 3. Fetch latest blockchain anchor
    cp_stmt = (
        select(MerkleCheckpoint)
        .where(MerkleCheckpoint.status == "CONFIRMED")
        .order_by(MerkleCheckpoint.tree_size.desc())
        .limit(1)
    )
    cp_res = await db.execute(cp_stmt)
    checkpoint = cp_res.scalar_one_or_none()

    doc_meta = {
        "case_id": version.case_id,
        "document_id": version.document_id,
        "version_id": version.version_id,
        "file_name": version.file_name,
        "mime_type": version.mime_type,
        "digest_sha256": version.digest,
        "size_bytes": version.size_bytes,
        "declared_capture_time": version.declared_capture_time.isoformat() if version.declared_capture_time else None,
        "committed_at": version.created_at.isoformat(),
    }

    audit_meta = {
        "sequence_id": audit_event.sequence_id,
        "event_type": audit_event.event_type,
        "event_hash": audit_event.event_hash,
        "signature": audit_event.signature,
        "signing_key_id": audit_event.signing_key_id,
    }

    anchor_meta = {
        "chain_id": 31337,
        "contract_address": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
        "tx_hash": checkpoint.tx_hash if checkpoint else "0x0000000000000000000000000000000000000000000000000000000000000000",
        "block_number": checkpoint.block_number if checkpoint else 1,
        "confirmed_at": checkpoint.confirmed_at.isoformat() if checkpoint and checkpoint.confirmed_at else None,
    }

    passport = generate_evidence_passport(
        document_meta=doc_meta,
        audit_event=audit_meta,
        merkle_proof=merkle_proof,
        blockchain_anchor=anchor_meta,
    )
    return passport


@router.post("/versions/{id}/derivatives", status_code=status.HTTP_201_CREATED)
async def create_derivative(
    id: str,
    req: DerivativeCreateRequest,
    db: AsyncSession = Depends(get_db),
    user: SessionUser = Depends(get_current_user),
):
    content_bytes = base64.b64decode(req.content_base64)
    child_ver = await lineage_service.register_derivative(
        session=db,
        parent_version_id=id,
        user=user,
        operation=req.operation,
        tool_name=req.tool_name,
        tool_version=req.tool_version,
        file_name=req.file_name,
        mime_type=req.mime_type,
        content_bytes=content_bytes,
    )
    await db.commit()

    return {
        "version_id": child_ver.version_id,
        "document_id": child_ver.document_id,
        "case_id": child_ver.case_id,
        "version_number": child_ver.version_number,
        "state": child_ver.state,
        "digest": child_ver.digest,
        "file_name": child_ver.file_name,
    }
