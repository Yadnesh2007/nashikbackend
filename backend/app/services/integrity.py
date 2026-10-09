"""Integrity Verification and Five-Minute Background Sweep Service."""

from typing import List, Dict, Any, Optional
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from evidenceshield_crypto import verify_evidence_integrity
from ..models.entities import DocumentVersion, IntegrityAlert, AuditEvent
from .storage import storage_service
from .vault import vault_client
from .audit import audit_service


class IntegrityService:
    """Performs ordered multi-stage verification and automated quarantine sweeps."""

    async def verify_version_integrity(
        self,
        session: AsyncSession,
        version_id: str,
    ) -> Dict[str, Any]:
        stmt = select(DocumentVersion).where(DocumentVersion.version_id == version_id)
        res = await session.execute(stmt)
        version = res.scalar_one_or_none()

        if not version:
            return {"is_valid": False, "failure_stage": "OBJECT_LOOKUP", "error": "Version not found."}

        ciphertext = await storage_service.get_ciphertext(version.object_key)
        dek = vault_client.unwrap_dek(version.wrapped_key)

        result = verify_evidence_integrity(
            ciphertext=ciphertext,
            dek=dek,
            nonce_b64=version.nonce,
            tag_b64=version.tag,
            case_id=version.case_id,
            document_id=version.document_id,
            version_id=version.version_id,
            format_mimetype=version.mime_type,
            committed_digest=version.digest,
        )

        if not result.is_valid:
            # Immediate Quarantine
            if version.state != "QUARANTINED":
                version.state = "QUARANTINED"
                version.quarantine_reason = f"Verification failed at stage {result.failure_stage.value}: {result.error_message}"

                alert = IntegrityAlert(
                    version_id=version.version_id,
                    case_id=version.case_id,
                    alert_type="CRYPTOGRAPHIC_FAILURE",
                    failure_stage=result.failure_stage.value,
                    error_details=result.error_message,
                    status="OPEN",
                )
                session.add(alert)

                await audit_service.append_event(
                    session=session,
                    event_type="INTEGRITY_VIOLATION_QUARANTINED",
                    actor_id="system-integrity-worker",
                    actor_role="SYSTEM_SERVICE",
                    actor_agency="EVIDENCESHIELD_CORE",
                    resource_type="document_version",
                    resource_id=version.version_id,
                    payload={
                        "failure_stage": result.failure_stage.value,
                        "error_code": result.error_code,
                        "error_message": result.error_message,
                    },
                )
                await session.flush()

        return {
            "version_id": version.version_id,
            "is_valid": result.is_valid,
            "failure_stage": result.failure_stage.value,
            "error_code": result.error_code,
            "error_message": result.error_message,
            "stage_durations_ms": result.stage_durations_ms,
        }

    async def run_integrity_sweep(self, session: AsyncSession) -> List[Dict[str, Any]]:
        """Sweeps all active document versions."""
        stmt = (
            select(DocumentVersion)
            .where(DocumentVersion.state.in_(["READY_PENDING_ANCHOR", "VERIFIED_ANCHORED"]))
        )
        res = await session.execute(stmt)
        versions = res.scalars().all()

        results = []
        for v in versions:
            r = await self.verify_version_integrity(session, v.version_id)
            results.append(r)

        return results


integrity_service = IntegrityService()
