"""Secure Ingestion Service with Bounded Upload and Authenticated Encryption."""

from datetime import datetime, timezone, timedelta
import json
import uuid
from typing import Optional, Dict, Any, Tuple

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from evidenceshield_crypto import (
    encrypt_version_bytes,
    compute_sha256_hex,
)
from ..models.entities import Case, Document, DocumentVersion, UploadSession, TransactionalOutbox
from .storage import storage_service
from .vault import vault_client
from .audit import audit_service
from ..core.security import SessionUser

MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB
MAX_PAGE_COUNT = 200
ALLOWED_MIME_TYPES = {
    "application/pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "text/plain",
    "image/jpeg",
    "image/png",
}


class IngestionService:
    """Manages upload session lifecycle, streaming AES-256-GCM encryption and storage."""

    async def create_upload_session(
        self,
        session: AsyncSession,
        case_id: str,
        user: SessionUser,
        file_name: str,
        mime_type: str,
        size_bytes: int,
        classification: str = "INTERNAL",
        declared_capture_time: Optional[datetime] = None,
        declared_timezone: Optional[str] = None,
    ) -> UploadSession:
        if size_bytes > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File exceeds maximum allowed size of {MAX_FILE_SIZE // (1024*1024)} MB.",
            )
        if mime_type not in ALLOWED_MIME_TYPES:
            raise HTTPException(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                detail=f"Unsupported MIME type: {mime_type}. Allowed: PDF, DOCX, TXT, JPG, PNG.",
            )

        upload_sess = UploadSession(
            case_id=case_id,
            created_by_id=user.user_id,
            file_name=file_name,
            mime_type=mime_type,
            size_bytes=size_bytes,
            classification=classification,
            declared_capture_time=declared_capture_time,
            declared_timezone=declared_timezone,
            state="PENDING",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
        )
        session.add(upload_sess)
        await session.flush()
        return upload_sess

    async def process_upload_content(
        self,
        session: AsyncSession,
        session_id: str,
        content_bytes: bytes,
        user: SessionUser,
    ) -> DocumentVersion:
        """Processes raw bytes: bounds check, AES-GCM encryption, S3 upload, audit event."""
        # 1. Fetch upload session
        stmt = select(UploadSession).where(UploadSession.session_id == session_id)
        res = await session.execute(stmt)
        upload_sess = res.scalar_one_or_none()

        if not upload_sess:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Upload session not found.")
        if upload_sess.state != "PENDING":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid session state: {upload_sess.state}")
        if datetime.now(timezone.utc) > upload_sess.expires_at.replace(tzinfo=timezone.utc):
            upload_sess.state = "EXPIRED"
            await session.flush()
            raise HTTPException(status_code=status.HTTP_410_GONE, detail="Upload session expired.")

        # 2. Validate size and basic parser check
        actual_size = len(content_bytes)
        if actual_size > MAX_FILE_SIZE:
            upload_sess.state = "FAILED"
            await session.flush()
            raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Uploaded file exceeds limit.")

        page_count = None
        if upload_sess.mime_type == "application/pdf":
            # Count page markers in PDF without loading heavyweight parser in main process
            page_count = max(1, content_bytes.count(b"/Type /Page") + content_bytes.count(b"/Type/Page"))
            if page_count > MAX_PAGE_COUNT:
                upload_sess.state = "FAILED"
                await session.flush()
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"PDF exceeds maximum page limit of {MAX_PAGE_COUNT} pages.",
                )

        # 3. Create or find Document entity
        doc_stmt = (
            select(Document)
            .where(Document.case_id == upload_sess.case_id)
            .where(Document.title == upload_sess.file_name)
        )
        doc_res = await session.execute(doc_stmt)
        document = doc_res.scalar_one_or_none()

        if not document:
            document = Document(
                case_id=upload_sess.case_id,
                title=upload_sess.file_name,
                classification=upload_sess.classification,
                created_by_id=user.user_id,
            )
            session.add(document)
            await session.flush()

        version_id = str(uuid.uuid4())
        object_key = f"{upload_sess.case_id}/{document.document_id}/{version_id}.bin"

        # 4. Invoke Crypto Engine: AES-256-GCM authenticated encryption bound to AAD
        ciphertext, nonce_b64, tag_b64, digest_sha256, raw_dek_hex = encrypt_version_bytes(
            plaintext=content_bytes,
            case_id=upload_sess.case_id,
            document_id=document.document_id,
            version_id=version_id,
            format_mimetype=upload_sess.mime_type,
        )

        # 5. Wrap DEK via Vault Transit
        raw_dek = bytes.fromhex(raw_dek_hex)
        wrapped_key, key_id = vault_client.wrap_dek(raw_dek)

        # 6. Store ciphertext in SeaweedFS S3
        await storage_service.put_ciphertext(object_key, ciphertext)

        # 7. Construct DocumentVersion record with state READY_PENDING_ANCHOR
        version = DocumentVersion(
            version_id=version_id,
            document_id=document.document_id,
            case_id=upload_sess.case_id,
            version_number=1,
            state="READY_PENDING_ANCHOR",
            digest=digest_sha256,
            size_bytes=actual_size,
            mime_type=upload_sess.mime_type,
            file_name=upload_sess.file_name,
            page_count=page_count,
            object_key=object_key,
            nonce=nonce_b64,
            tag=tag_b64,
            wrapped_key=wrapped_key,
            key_id=key_id,
            aad_json=json.dumps({
                "case_id": upload_sess.case_id,
                "document_id": document.document_id,
                "version_id": version_id,
                "format": upload_sess.mime_type,
            }),
            declared_capture_time=upload_sess.declared_capture_time,
            declared_timezone=upload_sess.declared_timezone,
            created_by_id=user.user_id,
        )
        session.add(version)

        # 8. Commit Monotonic Audit Event
        audit_event = await audit_service.append_event(
            session=session,
            event_type="DOCUMENT_INGESTED",
            actor_id=user.user_id,
            actor_role=user.role,
            actor_agency=user.agency,
            resource_type="document_version",
            resource_id=version_id,
            payload={
                "case_id": upload_sess.case_id,
                "document_id": document.document_id,
                "version_id": version_id,
                "digest": digest_sha256,
                "file_name": upload_sess.file_name,
                "mime_type": upload_sess.mime_type,
                "size_bytes": actual_size,
            },
        )
        version.signed_baseline = audit_event.signature

        # 9. Insert durable outbox task for automatic anchoring
        outbox = TransactionalOutbox(
            event_type="ANCHOR_CHECKPOINT_QUEUED",
            payload_json=json.dumps({"version_id": version_id, "case_id": upload_sess.case_id}),
        )
        session.add(outbox)

        upload_sess.state = "COMPLETED"
        await session.flush()
        return version


ingestion_service = IngestionService()
