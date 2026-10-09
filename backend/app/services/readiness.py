"""Evidence Readiness Preflight Checklist Service."""

from typing import Dict, Any, List
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.entities import Case, DocumentVersion, CustodyTransfer, IntegrityAlert


class ReadinessService:
    """Preflight readiness evaluation for judicial export and court submission.

    Strictly produces factual checklists of omissions and next actions.
    NEVER outputs admissibility or guilt scores.
    """

    async def evaluate_case_readiness(
        self,
        session: AsyncSession,
        case_id: str,
    ) -> Dict[str, Any]:
        # 1. Fetch versions for the case
        v_stmt = select(DocumentVersion).where(DocumentVersion.case_id == case_id)
        v_res = await session.execute(v_stmt)
        versions = v_res.scalars().all()

        # 2. Fetch transfers for the case
        t_stmt = select(CustodyTransfer).where(CustodyTransfer.case_id == case_id)
        t_res = await session.execute(t_stmt)
        transfers = t_res.scalars().all()

        # 3. Fetch integrity alerts
        a_stmt = (
            select(IntegrityAlert)
            .where(IntegrityAlert.case_id == case_id)
            .where(IntegrityAlert.status.in_(["OPEN", "INVESTIGATING"]))
        )
        a_res = await session.execute(a_stmt)
        open_alerts = a_res.scalars().all()

        checks: List[Dict[str, Any]] = []
        omissions: List[str] = []
        next_actions: List[str] = []

        # Check 1: Document Anchoring Status
        unanchored = [v for v in versions if v.state != "VERIFIED_ANCHORED"]
        if unanchored:
            passed = False
            detail = f"{len(unanchored)} evidence version(s) are not verified/anchored on-chain."
            omissions.append("Blockchain anchor confirmation missing for active versions.")
            next_actions.append("Publish Merkle checkpoint and confirm Anvil chain transaction receipt.")
        else:
            passed = True
            detail = f"All {len(versions)} evidence version(s) are confirmed anchored with cryptographic proof."

        checks.append({
            "name": "Cryptographic Blockchain Anchoring",
            "passed": passed,
            "detail": detail,
        })

        # Check 2: Custody Chain Integrity (No unacknowledged pending transfers)
        pending_transfers = [t for t in transfers if t.state == "PENDING"]
        if pending_transfers:
            passed = False
            detail = f"{len(pending_transfers)} custody handoff(s) are unacknowledged."
            omissions.append("Unacknowledged custody transfers detected in case timeline.")
            next_actions.append("Designated recipients must formally accept or reject pending transfers.")
        else:
            passed = True
            detail = "All custody handoffs have formal platform-signed receipts."

        checks.append({
            "name": "Chain of Custody Completeness",
            "passed": passed,
            "detail": detail,
        })

        # Check 3: Active Integrity Alerts
        if open_alerts:
            passed = False
            detail = f"{len(open_alerts)} unresolved integrity alert(s) on case evidence."
            omissions.append("Unreviewed cryptographic or bit-flip alerts exist.")
            next_actions.append("Authorized reviewer must conduct technical review and record disposition.")
        else:
            passed = True
            detail = "Zero active integrity alerts. All versions verified."

        checks.append({
            "name": "Integrity Alert Disposition",
            "passed": passed,
            "detail": detail,
        })

        # Check 4: Quarantined Documents
        quarantined = [v for v in versions if v.state == "QUARANTINED"]
        if quarantined:
            omissions.append(f"{len(quarantined)} version(s) in QUARANTINED state.")
            next_actions.append("Investigate quarantined records; export cannot include unverified evidence.")

        is_ready = len(omissions) == 0

        return {
            "case_id": case_id,
            "is_ready": is_ready,
            "checks": checks,
            "omissions": omissions,
            "next_actions": next_actions,
        }


readiness_service = ReadinessService()
