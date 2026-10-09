"""Verified Retrieval Service with Cryptographic Re-Authentication."""

from typing import Tuple, Optional
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from evidenceshield_crypto import (
    decrypt_version_bytes,
    verify_evidence_integrity,
    CiphertextAuthError,
    DigestMismatchError,
)
from ..models.entities import DocumentVersion, Document, Case, CaseAssignment, DocumentGrant, IntegrityAlert
from .storage import storage_service
from .vault import vault_client
from .audit import audit_service
from ..core.security import SessionUser
from ..core.opa import check_permission


class RetrievalService:
    """Authenticates and decrypts evidence, verifying all stages before releasing bytes."""

    async def retrieve_verified_content(
        self,
        session: AsyncSession,
        version_id: str,
        user: SessionUser,
    ) -> Tuple[bytes, DocumentVersion]:
        # 1. Fetch version and document metadata
        stmt = (
            select(DocumentVersion, Document, Case)
            .join(Document, DocumentVersion.document_id == Document.document_id)
            .join(Case, DocumentVersion.case_id == Case.case_id)
            .where(DocumentVersion.version_id == version_id)
        )
        res = await session.execute(stmt)
        row = res.first()

        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence version not found.")

        version, doc, case = row

        # Invariant: Block ordinary retrieval of quarantined evidence
        if version.state == "QUARANTINED":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Resource is quarantined due to integrity violation: {version.quarantine_reason}. Download blocked.",
            )

        # 2. Gather case assignments and explicit grants for OPA check
        assign_stmt = select(CaseAssignment).where(CaseAssignment.case_id == version.case_id)
        assign_res = await session.execute(assign_stmt)
        assignments = assign_res.scalars().all()

        grant_stmt = (
            select(DocumentGrant)
            .where(DocumentGrant.document_id == version.document_id)
            .where(DocumentGrant.revoked_at.is_(None))
        )
        grant_res = await session.execute(grant_stmt)
        grants = grant_res.scalars().all()

        resource_ctx = {
            "type": "version",
            "case_id": version.case_id,
            "document_id": version.document_id,
            "version_id": version.version_id,
            "classification": doc.classification,
            "state": version.state,
            "uploader_id": version.created_by_id,
            "assigned_principals": [a.principal_id for a in assignments],
            "assigned_agencies": [a.agency for a in assignments],
            "explicit_grants": [
                {
                    "principal_id": g.principal_id,
                    "actions": g.actions.split(",") if isinstance(g.actions, str) else g.actions,
                    "expired": False,
                }
                for g in grants
            ],
        }

        # Zero-Trust OPA Authorization Check
        await check_permission(user, "document:download", resource_ctx)

        # 3. Retrieve ciphertext from storage
        ciphertext = await storage_service.get_ciphertext(version.object_key)
        if not ciphertext:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Ciphertext blob missing from storage.",
            )

        # 4. Unwrap DEK via Vault Transit
        dek = vault_client.unwrap_dek(version.wrapped_key)

        # 5. Authenticated AES-256-GCM Decryption and Plaintext Digest Verification
        try:
            plaintext = decrypt_version_bytes(
                ciphertext=ciphertext,
                dek=dek,
                nonce_b64=version.nonce,
                tag_b64=version.tag,
                case_id=version.case_id,
                document_id=version.document_id,
                version_id=version.version_id,
                format_mimetype=version.mime_type,
                expected_digest=version.digest,
            )
        except CiphertextAuthError as exc:
            # Automatically quarantine on corruption!
            version.state = "QUARANTINED"
            version.quarantine_reason = f"Ciphertext authentication failed: {exc}"
            alert = IntegrityAlert(
                version_id=version.version_id,
                case_id=version.case_id,
                alert_type="BIT_FLIP_CORRUPTION",
                failure_stage="CIPHERTEXT_AUTH",
                error_details=str(exc),
                status="OPEN",
            )
            session.add(alert)
            await audit_service.append_event(
                session=session,
                event_type="INTEGRITY_VIOLATION_QUARANTINED",
                actor_id=user.user_id,
                actor_role=user.role,
                actor_agency=user.agency,
                resource_type="document_version",
                resource_id=version.version_id,
                payload={"error_stage": "CIPHERTEXT_AUTH", "detail": str(exc)},
            )
            await session.commit()

            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Cryptographic integrity failure: AES-GCM tag mismatch. Evidence quarantined.",
            )
        except DigestMismatchError as exc:
            version.state = "QUARANTINED"
            version.quarantine_reason = f"Plaintext SHA-256 mismatch: {exc}"
            session.add(IntegrityAlert(
                version_id=version.version_id,
                case_id=version.case_id,
                alert_type="DIGEST_TAMPERING",
                failure_stage="DIGEST_VERIFICATION",
                error_details=str(exc),
                status="OPEN",
            ))
            await session.commit()
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Cryptographic integrity failure: Digest mismatch. Evidence quarantined.",
            )

        # 6. Audit retrieval event
        await audit_service.append_event(
            session=session,
            event_type="DOCUMENT_VERIFIED_RETRIEVED",
            actor_id=user.user_id,
            actor_role=user.role,
            actor_agency=user.agency,
            resource_type="document_version",
            resource_id=version.version_id,
            payload={"digest": version.digest},
        )

        return plaintext, version


retrieval_service = RetrievalService()
