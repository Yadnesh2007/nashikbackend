"""AI Analysis, Cited Summaries, and Inconsistency Review Routes."""

from typing import List, Optional
import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...core.database import get_db
from ...core.security import SessionUser, get_current_user
from ...models.entities import DocumentVersion, AnalysisArtifact, InconsistencyReview
from ...services.retrieval import retrieval_service
from ...services.ai_review import ai_review_service

router = APIRouter(prefix="", tags=["AI & Case Analysis"])


class AnalysisTriggerRequest(BaseModel):
    analysis_type: str  # SUMMARY, TIMELINE, INCONSISTENCY
    document_version_ids: List[str]


class InconsistencyReviewRequest(BaseModel):
    human_disposition: str  # CONFIRMED or DISMISSED
    rationale: str


@router.post("/cases/{id}/analysis", status_code=status.HTTP_202_ACCEPTED)
async def trigger_case_analysis(
    id: str,
    req: AnalysisTriggerRequest,
    db: AsyncSession = Depends(get_db),
    user: SessionUser = Depends(get_current_user),
):
    # 1. Decrypt authorized plaintext in memory (never storing shared plaintext index)
    extracted_texts = {}
    for v_id in req.document_version_ids:
        try:
            pt, ver = await retrieval_service.retrieve_verified_content(db, v_id, user)
            extracted_texts[v_id] = pt.decode("utf-8", errors="ignore")
        except Exception:
            pass

    if req.analysis_type == "SUMMARY":
        res = await ai_review_service.generate_summary(
            session=db,
            case_id=id,
            user=user,
            version_ids=req.document_version_ids,
            extracted_texts=extracted_texts,
        )
        await db.commit()
        return {
            "job_id": str(uuid.uuid4()),
            "status": "COMPLETED",
            "result": res,
        }

    elif req.analysis_type == "INCONSISTENCY":
        findings = await ai_review_service.detect_inconsistencies(
            session=db,
            case_id=id,
            user=user,
            extracted_texts=extracted_texts,
        )
        await db.commit()
        return {
            "job_id": str(uuid.uuid4()),
            "status": "COMPLETED",
            "findings": findings,
        }

    return {"job_id": str(uuid.uuid4()), "status": "QUEUED"}


@router.post("/analysis/inconsistencies/{review_id}/review")
async def review_inconsistency(
    review_id: str,
    req: InconsistencyReviewRequest,
    db: AsyncSession = Depends(get_db),
    user: SessionUser = Depends(get_current_user),
):
    stmt = select(InconsistencyReview).where(InconsistencyReview.review_id == review_id)
    res = await db.execute(stmt)
    review = res.scalar_one_or_none()
    if not review:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")

    review.human_disposition = req.human_disposition
    review.rationale = req.rationale
    review.reviewer_id = user.user_id

    await db.commit()
    return {
        "review_id": review.review_id,
        "human_disposition": review.human_disposition,
        "rationale": review.rationale,
    }
