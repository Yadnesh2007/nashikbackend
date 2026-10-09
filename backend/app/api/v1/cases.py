"""Cases and Ingestion Routes."""

from datetime import datetime, timezone
import json
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...core.database import get_db
from ...core.security import SessionUser, get_current_user
from ...core.opa import check_permission
from ...models.entities import Case, CaseAssignment, Document, DocumentVersion, DocumentGrant, UploadSession
from ...services.ingestion import ingestion_service
from ...services.readiness import readiness_service
from ...services.audit import audit_service

router = APIRouter(prefix="", tags=["Cases & Ingestion"])


class CaseCreateRequest(BaseModel):
    case_number: str
    title: str
    description: Optional[str] = None
    agency: str


class GrantCreateRequest(BaseModel):
    document_id: Optional[str] = None
    principal_id: str
    actions: List[str]
    expires_at: Optional[datetime] = None


class UploadSessionCreateRequest(BaseModel):
    file_name: str
    mime_type: str
    size_bytes: int
    classification: str = "INTERNAL"
    declared_capture_time: Optional[datetime] = None
    declared_timezone: Optional[str] = None


@router.get("/cases")
async def list_cases(
    limit: int = 20,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    user: SessionUser = Depends(get_current_user),
):
    stmt = select(Case).offset(offset).limit(limit)
    res = await db.execute(stmt)
    cases = res.scalars().all()
    return {
        "items": [
            {
                "case_id": c.case_id,
                "case_number": c.case_number,
                "title": c.title,
                "description": c.description,
                "agency": c.agency,
                "lead_investigator_id": c.lead_investigator_id,
                "created_at": c.created_at,
            }
            for c in cases
        ],
        "total": len(cases),
        "limit": limit,
        "offset": offset,
    }


@router.post("/cases", status_code=status.HTTP_201_CREATED)
async def create_case(
    req: CaseCreateRequest,
    db: AsyncSession = Depends(get_db),
    user: SessionUser = Depends(get_current_user),
):
    case = Case(
        case_number=req.case_number,
        title=req.title,
        description=req.description,
        agency=req.agency,
        lead_investigator_id=user.user_id,
    )
    db.add(case)
    await db.flush()

    # Assign creator as lead
    assignment = CaseAssignment(
        case_id=case.case_id,
        principal_id=user.user_id,
        role=user.role,
        agency=user.agency,
    )
    db.add(assignment)

    await audit_service.append_event(
        session=db,
        event_type="CASE_CREATED",
        actor_id=user.user_id,
        actor_role=user.role,
        actor_agency=user.agency,
        resource_type="case",
        resource_id=case.case_id,
        payload={"case_number": case.case_number, "agency": case.agency},
    )
    await db.commit()

    return {
        "case_id": case.case_id,
        "case_number": case.case_number,
        "title": case.title,
        "description": case.description,
        "agency": case.agency,
        "lead_investigator_id": case.lead_investigator_id,
        "created_at": case.created_at,
    }


@router.get("/cases/{id}")
async def get_case_detail(
    id: str,
    db: AsyncSession = Depends(get_db),
    user: SessionUser = Depends(get_current_user),
):
    stmt = select(Case).where(Case.case_id == id)
    res = await db.execute(stmt)
    case = res.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found.")

    # Authorization Check
    assign_stmt = select(CaseAssignment).where(CaseAssignment.case_id == id)
    assign_res = await db.execute(assign_stmt)
    assignments = assign_res.scalars().all()

    resource_ctx = {
        "type": "case",
        "case_id": id,
        "assigned_principals": [a.principal_id for a in assignments],
        "assigned_agencies": [a.agency for a in assignments],
    }
    await check_permission(user, "case:read", resource_ctx)

    # Fetch documents
    doc_stmt = select(Document).where(Document.case_id == id)
    doc_res = await db.execute(doc_stmt)
    documents = doc_res.scalars().all()

    doc_summaries = []
    for d in documents:
        # Get latest version
        v_stmt = (
            select(DocumentVersion)
            .where(DocumentVersion.document_id == d.document_id)
            .order_by(DocumentVersion.version_number.desc())
            .limit(1)
        )
        v_res = await db.execute(v_stmt)
        latest_ver = v_res.scalar_one_or_none()

        doc_summaries.append({
            "document_id": d.document_id,
            "title": d.title,
            "classification": d.classification,
            "current_version_id": latest_ver.version_id if latest_ver else None,
            "current_state": latest_ver.state if latest_ver else "INGESTING",
        })

    return {
        "case_id": case.case_id,
        "case_number": case.case_number,
        "title": case.title,
        "description": case.description,
        "agency": case.agency,
        "lead_investigator_id": case.lead_investigator_id,
        "created_at": case.created_at,
        "documents": doc_summaries,
    }


@router.post("/cases/{id}/grants", status_code=status.HTTP_201_CREATED)
async def create_grant(
    id: str,
    req: GrantCreateRequest,
    db: AsyncSession = Depends(get_db),
    user: SessionUser = Depends(get_current_user),
):
    # Enforce fresh MFA (<10 min) for grants
    if not user.is_mfa_fresh:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Granting access requires fresh MFA verification.",
        )

    grant = DocumentGrant(
        document_id=req.document_id or id,
        case_id=id,
        principal_id=req.principal_id,
        granted_by_id=user.user_id,
        actions=json.dumps(req.actions),
        expires_at=req.expires_at,
    )
    db.add(grant)

    await audit_service.append_event(
        session=db,
        event_type="GRANT_ISSUED",
        actor_id=user.user_id,
        actor_role=user.role,
        actor_agency=user.agency,
        resource_type="document_grant",
        resource_id=grant.grant_id,
        payload={"principal_id": req.principal_id, "actions": req.actions},
    )
    await db.commit()

    return {
        "grant_id": grant.grant_id,
        "principal_id": grant.principal_id,
        "actions": req.actions,
        "created_at": grant.created_at,
    }


@router.post("/cases/{id}/upload-sessions", status_code=status.HTTP_201_CREATED)
async def create_upload_session(
    id: str,
    req: UploadSessionCreateRequest,
    db: AsyncSession = Depends(get_db),
    user: SessionUser = Depends(get_current_user),
):
    sess = await ingestion_service.create_upload_session(
        session=db,
        case_id=id,
        user=user,
        file_name=req.file_name,
        mime_type=req.mime_type,
        size_bytes=req.size_bytes,
        classification=req.classification,
        declared_capture_time=req.declared_capture_time,
        declared_timezone=req.declared_timezone,
    )
    await db.commit()
    return {
        "session_id": sess.session_id,
        "case_id": sess.case_id,
        "file_name": sess.file_name,
        "expires_at": sess.expires_at,
    }


@router.put("/upload-sessions/{id}/content")
async def stream_upload_content(
    id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: SessionUser = Depends(get_current_user),
):
    body_bytes = await request.body()
    version = await ingestion_service.process_upload_content(
        session=db,
        session_id=id,
        content_bytes=body_bytes,
        user=user,
    )
    await db.commit()

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
    }


@router.get("/cases/{id}/readiness")
async def get_case_readiness(
    id: str,
    db: AsyncSession = Depends(get_db),
    user: SessionUser = Depends(get_current_user),
):
    return await readiness_service.evaluate_case_readiness(db, id)
