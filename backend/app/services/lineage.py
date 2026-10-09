"""Derivative Lineage and Forensic Transformation Service."""

import base64
import json
import uuid
from typing import Optional, Dict, Any

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from evidenceshield_crypto import encrypt_version_bytes, compute_sha256_hex
from ..models.entities import DocumentVersion, DerivativeLineage, Document
from .storage import storage_service
from .vault import vault_client
from .audit import audit_service
from ..core.security import SessionUser


class LineageService:
    """Registers immutable forensic derivatives and maintains parent-child lineage graphs."""

    async def register_derivative(
        self,
        session: AsyncSession,
        parent_version_id: str,
        user: SessionUser,
        operation: str,
        tool_name: str,
        tool_version: str,
        file_name: str,
        mime_type: str,
        content_bytes: bytes,
    ) -> DocumentVersion:
        # 1. Fetch parent version
        p_stmt = select(DocumentVersion).where(DocumentVersion.version_id == parent_version_id)
        p_res = await session.execute(p_stmt)
        parent = p_res.scalar_one_or_none()

        if not parent:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Parent version not found.")

        # Invariant: Parent must be verified/anchored
        if parent.state not in ["READY_PENDING_ANCHOR", "VERIFIED_ANCHORED"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot derive from version in state '{parent.state}'.",
            )

        # 2. Encrypt child version bytes
        child_version_id = str(uuid.uuid4())
        object_key = f"{parent.case_id}/{parent.document_id}/{child_version_id}.bin"

        ciphertext, nonce_b64, tag_b64, child_digest, raw_dek_hex = encrypt_version_bytes(
            plaintext=content_bytes,
            case_id=parent.case_id,
            document_id=parent.document_id,
            version_id=child_version_id,
            format_mimetype=mime_type,
        )

        wrapped_key, key_id = vault_client.wrap_dek(bytes.fromhex(raw_dek_hex))
        await storage_service.put_ciphertext(object_key, ciphertext)

        # 3. Create child DocumentVersion
        child_version = DocumentVersion(
            version_id=child_version_id,
            document_id=parent.document_id,
            case_id=parent.case_id,
            version_number=parent.version_number + 1,
            state="VERIFIED_ANCHORED",  # Automatically verified under active system pipeline
            digest=child_digest,
            size_bytes=len(content_bytes),
            mime_type=mime_type,
            file_name=file_name,
            object_key=object_key,
            nonce=nonce_b64,
            tag=tag_b64,
            wrapped_key=wrapped_key,
            key_id=key_id,
            aad_json=json.dumps({
                "case_id": parent.case_id,
                "document_id": parent.document_id,
                "version_id": child_version_id,
                "format": mime_type,
            }),
            created_by_id=user.user_id,
        )
        session.add(child_version)

        # 4. Create DerivativeLineage link
        lineage = DerivativeLineage(
            parent_version_id=parent.version_id,
            child_version_id=child_version_id,
            operation=operation,
            tool_name=tool_name,
            tool_version=tool_version,
            operator_id=user.user_id,
            input_digest=parent.digest,
            output_digest=child_digest,
        )
        session.add(lineage)

        # 5. Commit audit event
        await audit_service.append_event(
            session=session,
            event_type="DERIVATIVE_VERSION_CREATED",
            actor_id=user.user_id,
            actor_role=user.role,
            actor_agency=user.agency,
            resource_type="derivative_lineage",
            resource_id=child_version_id,
            payload={
                "parent_version_id": parent.version_id,
                "child_version_id": child_version_id,
                "operation": operation,
                "tool_name": tool_name,
                "tool_version": tool_version,
                "input_digest": parent.digest,
                "output_digest": child_digest,
            },
        )

        await session.flush()
        return child_version


lineage_service = LineageService()
