"""Idempotent Synthetic Seeding Script for EvidenceShield AI."""

import asyncio
import json
import os
import sys

from sqlalchemy import select

# Ensure project paths are in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../crypto")))

from backend.app.core.database import AsyncSessionLocal, init_db
from backend.app.models.entities import Case, CaseAssignment, Document, DocumentVersion
from backend.app.services.ingestion import ingestion_service
from backend.app.services.anchoring import anchoring_service
from backend.app.core.security import SessionUser


async def seed_all():
    print("[*] Initializing database schema...")
    await init_db()

    manifest_path = "fixtures/manifest.json"
    if not os.path.exists(manifest_path):
        print(f"[!] Fixtures manifest not found at {manifest_path}")
        return

    with open(manifest_path, "r") as f:
        manifest = json.load(f)

    async with AsyncSessionLocal() as session:
        # 1. Seed Cases and Assignments
        print("[*] Seeding cases and assignments...")
        for c_data in manifest.get("seed_cases", []):
            stmt = select(Case).where(Case.case_id == c_data["case_id"])
            res = await session.execute(stmt)
            existing_case = res.scalar_one_or_none()

            if not existing_case:
                case = Case(
                    case_id=c_data["case_id"],
                    case_number=c_data["case_number"],
                    title=c_data["title"],
                    agency=c_data["agency"],
                    lead_investigator_id=c_data["lead_investigator_id"],
                )
                session.add(case)
                await session.flush()

                # Add assignments
                for p_id in c_data.get("assigned_principals", []):
                    # Find role from seed_users
                    user_info = next(
                        (u for u in manifest.get("seed_users", []) if u["username"] == p_id),
                        {"role": "POLICE", "agency": c_data["agency"]},
                    )
                    assignment = CaseAssignment(
                        case_id=case.case_id,
                        principal_id=p_id,
                        role=user_info.get("role", "POLICE"),
                        agency=user_info.get("agency", c_data["agency"]),
                    )
                    session.add(assignment)

        await session.commit()

        # 2. Seed Baseline Documents
        print("[*] Seeding baseline documents and versions...")
        for doc_info in manifest.get("seed_documents", []):
            d_stmt = select(Document).where(Document.document_id == doc_info["document_id"])
            d_res = await session.execute(d_stmt)
            if not d_res.scalar_one_or_none():
                # Read fixture file
                f_path = doc_info["file"]["path"]
                if not os.path.exists(f_path):
                    continue
                with open(f_path, "rb") as f:
                    file_bytes = f.read()

                mock_user = SessionUser(
                    user_id="officer_sharma",
                    username="officer_sharma",
                    role="POLICE",
                    agency="MUMBAI_CRIME_BRANCH",
                )

                upload_sess = await ingestion_service.create_upload_session(
                    session=session,
                    case_id=doc_info["case_id"],
                    user=mock_user,
                    file_name=os.path.basename(f_path),
                    mime_type="application/pdf" if f_path.endswith(".pdf") else "text/plain",
                    size_bytes=len(file_bytes),
                    classification=doc_info.get("classification", "INTERNAL"),
                )

                version = await ingestion_service.process_upload_content(
                    session=session,
                    session_id=upload_sess.session_id,
                    content_bytes=file_bytes,
                    user=mock_user,
                )

        await session.commit()

        # 3. Create initial Merkle checkpoint and publish anchor
        print("[*] Publishing initial Merkle checkpoint to blockchain anchor...")
        try:
            cp = await anchoring_service.create_and_publish_checkpoint(session)
            print(f"[+] Anchored checkpoint: {cp.checkpoint_id} (tree_size={cp.tree_size}, root={cp.root_hash})")
            await session.commit()
        except Exception as exc:
            print(f"[-] Anchoring checkpoint info: {exc}")

    print("[SUCCESS] Database seeded successfully with common baseline fixtures.")


if __name__ == "__main__":
    asyncio.run(seed_all())
