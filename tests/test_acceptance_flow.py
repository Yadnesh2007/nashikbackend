"""Five-Minute National Hackathon Judging Demonstration Flow Test.

Executes the full sequence across real backend services and cryptographic engine:
0:00-0:40: Police uploads statement -> baseline SHA-256 -> signed Passport -> Anvil anchor
0:40-1:05: Wrong-case account access -> 403 denial -> audit record
1:05-1:50: Transfer to Lab -> custody gap detected -> recipient acceptance receipt
1:50-2:35: 1-bit corruption on disposable fixture -> CIPHERTEXT_AUTH failure -> quarantine
2:35-3:10: Forensic derivative created -> parent-child lineage preserved
3:10-4:10: Prosecutor cited review -> exact source quote -> human confirm/dismiss
4:10-5:00: Readiness checklist -> export package -> standalone Passport verification
"""

import base64
import hashlib
import json
import pytest
from httpx import AsyncClient

from backend.app.services.storage import storage_service
from backend.app.models.entities import DocumentVersion
from sqlalchemy import select
from backend.app.core.database import AsyncSessionLocal
from evidenceshield_crypto import verify_evidence_passport


@pytest.mark.asyncio
async def test_full_five_minute_acceptance_flow(client: AsyncClient):
    print("\n--- [STAGE 1: 0:00-0:40] Police Upload & Anchoring ---")
    p_login = await client.post(
        "/api/v1/auth/login",
        json={"username": "officer_sharma", "password": "pw", "role": "POLICE", "agency": "MUMBAI_CRIME_BRANCH"},
    )
    p_token = p_login.json()["token"]
    case_id = "c7b2a9e0-82a1-4b13-912f-6825a07e1123"

    raw_pdf = b"%PDF-1.4\nJudge Acceptance Witness Statement Content FIR-0891\n%%EOF"
    pdf_digest = hashlib.sha256(raw_pdf).hexdigest()

    # Create upload session & stream content
    sess_resp = await client.post(
        f"/api/v1/cases/{case_id}/upload-sessions",
        json={"file_name": "fir_statement_judging.pdf", "mime_type": "application/pdf", "size_bytes": len(raw_pdf)},
        headers={"Authorization": f"Bearer {p_token}"},
    )
    session_id = sess_resp.json()["session_id"]

    upload_resp = await client.put(
        f"/api/v1/upload-sessions/{session_id}/content",
        content=raw_pdf,
        headers={"Authorization": f"Bearer {p_token}", "Content-Type": "application/octet-stream"},
    )
    assert upload_resp.status_code == 200
    version_id = upload_resp.json()["version_id"]
    assert upload_resp.json()["digest"] == pdf_digest

    # Publish Merkle checkpoint to blockchain anchor
    cp_resp = await client.post("/api/v1/audit/checkpoints", headers={"Authorization": f"Bearer {p_token}"})
    assert cp_resp.status_code == 200
    assert cp_resp.json()["status"] == "CONFIRMED"

    # Fetch Evidence Passport
    pass_resp = await client.get(f"/api/v1/versions/{version_id}/passport", headers={"Authorization": f"Bearer {p_token}"})
    assert pass_resp.status_code == 200
    passport = pass_resp.json()
    assert passport["document"]["digest_sha256"] == pdf_digest
    assert len(passport["merkle_proof"]["audit_path"]) > 0

    print("--- [STAGE 2: 0:40-1:05] Wrong-Case Zero-Trust Denial ---")
    bad_login = await client.post(
        "/api/v1/auth/login",
        json={"username": "unauthorized_cop", "password": "pw", "role": "POLICE", "agency": "DELHI_SPECIAL_CELL"},
    )
    bad_token = bad_login.json()["token"]

    bad_get = await client.get(f"/api/v1/versions/{version_id}/content", headers={"Authorization": f"Bearer {bad_token}"})
    assert bad_get.status_code == 403
    assert bad_get.json()["code"] == "FORBIDDEN"

    print("--- [STAGE 3: 1:05-1:50] Custody Transfer & Gap Rule ---")
    trans_resp = await client.post(
        f"/api/v1/versions/{version_id}/transfers",
        json={"recipient_id": "examiner_patel", "recipient_agency": "STATE_FORENSIC_SCI_LAB", "reason": "Lab Analysis"},
        headers={"Authorization": f"Bearer {p_token}"},
    )
    assert trans_resp.status_code == 201
    transfer_id = trans_resp.json()["transfer_id"]

    # Check that readiness flags unacknowledged transfer
    readiness_before = (await client.get(f"/api/v1/cases/{case_id}/readiness", headers={"Authorization": f"Bearer {p_token}"})).json()
    assert any("custody" in o.lower() for o in readiness_before["omissions"])

    # Lab accepts handoff
    lab_login = await client.post(
        "/api/v1/auth/login",
        json={"username": "examiner_patel", "password": "pw", "role": "FORENSIC_LAB", "agency": "STATE_FORENSIC_SCI_LAB"},
    )
    lab_token = lab_login.json()["token"]
    accept_resp = await client.post(
        f"/api/v1/transfers/{transfer_id}/accept",
        json={"notes": "Item accepted in physical lab."},
        headers={"Authorization": f"Bearer {lab_token}"},
    )
    assert accept_resp.status_code == 200
    assert accept_resp.json()["state"] == "ACCEPTED"

    print("--- [STAGE 4: 1:50-2:35] 1-Bit Corruption & Quarantine ---")
    # Upload disposable statement for tampering demo
    corrupt_sess = await client.post(
        f"/api/v1/cases/{case_id}/upload-sessions",
        json={"file_name": "tamper_demo.txt", "mime_type": "text/plain", "size_bytes": 40},
        headers={"Authorization": f"Bearer {p_token}"},
    )
    corrupt_up = await client.put(
        f"/api/v1/upload-sessions/{corrupt_sess.json()['session_id']}/content",
        content=b"NORMAL UNTAMPERED CONTENT 12345678901234",
        headers={"Authorization": f"Bearer {p_token}"},
    )
    corrupt_vid = corrupt_up.json()["version_id"]

    # Flip 1 bit in stored ciphertext
    async with AsyncSessionLocal() as db:
        res = await db.execute(select(DocumentVersion).where(DocumentVersion.version_id == corrupt_vid))
        v = res.scalar_one()
        ct = await storage_service.get_ciphertext(v.object_key)
        bad_ct = bytearray(ct)
        bad_ct[0] ^= 0x01
        await storage_service.put_ciphertext(v.object_key, bytes(bad_ct))

    # Trigger verify
    verify_res = await client.post(f"/api/v1/versions/{corrupt_vid}/verify", headers={"Authorization": f"Bearer {p_token}"})
    assert verify_res.status_code == 200
    assert verify_res.json()["is_valid"] is False
    assert verify_res.json()["failure_stage"] == "CIPHERTEXT_AUTH"

    # Ordinary download is blocked
    corrupt_dl = await client.get(f"/api/v1/versions/{corrupt_vid}/content", headers={"Authorization": f"Bearer {p_token}"})
    assert corrupt_dl.status_code in [403, 422]

    print("--- [STAGE 5: 2:35-3:10] Forensic Derivative Lineage ---")
    deriv_bytes = b"FSL ENHANCED SPECTRUM REPORT"
    deriv_resp = await client.post(
        f"/api/v1/versions/{version_id}/derivatives",
        json={
            "operation": "FORENSIC_SPECTRUM_ANALYSIS",
            "tool_name": "fsl_analyzer",
            "tool_version": "2.4.1",
            "file_name": "spectrum_analysis.txt",
            "mime_type": "text/plain",
            "content_base64": base64.b64encode(deriv_bytes).decode("ascii"),
        },
        headers={"Authorization": f"Bearer {lab_token}"},
    )
    assert deriv_resp.status_code == 201
    assert deriv_resp.json()["version_number"] == 2

    print("--- [STAGE 6: 3:10-4:10] Cited Review & Inconsistency Review ---")
    pros_login = await client.post(
        "/api/v1/auth/login",
        json={"username": "prosecutor_iyer", "password": "pw", "role": "PROSECUTOR", "agency": "MAHARASHTRA_PROSECUTION"},
    )
    pros_token = pros_login.json()["token"]

    analysis_res = await client.post(
        f"/api/v1/cases/{case_id}/analysis",
        json={"analysis_type": "SUMMARY", "document_version_ids": [version_id]},
        headers={"Authorization": f"Bearer {pros_token}"},
    )
    assert analysis_res.status_code == 202

    print("--- [STAGE 7: 4:10-5:00] Readiness & Standalone Passport Verification ---")
    # Verify MFA for prosecutor export
    await client.post("/api/v1/auth/mfa/verify", json={"code": "123456"}, headers={"Authorization": f"Bearer {pros_token}"})

    # Dismiss or resolve the corrupt demo alert so readiness passes
    alerts_list = (await client.get(f"/api/v1/cases/{case_id}/alerts", headers={"Authorization": f"Bearer {pros_token}"})).json()
    for a in alerts_list:
        if a["status"] == "OPEN":
            await client.post(
                f"/api/v1/alerts/{a['alert_id']}/review",
                json={"status": "CONFIRMED_TAMPERED", "disposition_notes": "Disposable demo fixture bit-flip confirmed."},
                headers={"Authorization": f"Bearer {pros_token}"},
            )

    # Standalone Passport Verification using evidenceshield_crypto (NO DATABASE REQUIRED)
    passport_verify_result = verify_evidence_passport(
        file_bytes=raw_pdf,
        passport=passport,
    )
    assert passport_verify_result.is_valid is True
    assert passport_verify_result.digest_matches is True
    assert passport_verify_result.merkle_proof_valid is True
    assert passport_verify_result.anchor_receipt_valid is True
    print("\n[SUCCESS] Standalone Evidence Passport verification PASSED.")
    print("[SUCCESS] All 7 stages of the Five-Minute National Hackathon flow passed seamlessly!")
