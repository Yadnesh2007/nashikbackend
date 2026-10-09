"""Test 1-Bit Corruption Detection, Multi-Stage Errors, and Quarantine."""

import os
import pytest
from httpx import AsyncClient
from backend.app.services.storage import storage_service
from backend.app.models.entities import DocumentVersion
from sqlalchemy import select
from backend.app.core.database import AsyncSessionLocal


@pytest.mark.asyncio
async def test_one_bit_corruption_automatic_quarantine(client: AsyncClient):
    # 1. Login as Officer Sharma
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"username": "officer_sharma", "password": "pw", "role": "POLICE", "agency": "MUMBAI_CRIME_BRANCH"},
    )
    token = login_resp.json()["token"]
    case_id = "c7b2a9e0-82a1-4b13-912f-6825a07e1123"

    # 2. Upload disposable test statement
    raw_content = b"DISPOSABLE STATEMENT FOR BIT FLIP CORRUPTION HARNESS 2026"
    sess_resp = await client.post(
        f"/api/v1/cases/{case_id}/upload-sessions",
        json={"file_name": "tamper_test.txt", "mime_type": "text/plain", "size_bytes": len(raw_content)},
        headers={"Authorization": f"Bearer {token}"},
    )
    session_id = sess_resp.json()["session_id"]

    upload_resp = await client.put(
        f"/api/v1/upload-sessions/{session_id}/content",
        content=raw_content,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/octet-stream"},
    )
    version_id = upload_resp.json()["version_id"]

    # 3. Simulate bit-flip tampering on storage ciphertext (disposable harness)
    async with AsyncSessionLocal() as db:
        stmt = select(DocumentVersion).where(DocumentVersion.version_id == version_id)
        res = await db.execute(stmt)
        v = res.scalar_one()
        object_key = v.object_key

        ct = await storage_service.get_ciphertext(object_key)
        corrupted_ct = bytearray(ct)
        corrupted_ct[0] ^= 0x01  # Flip bit 0
        await storage_service.put_ciphertext(object_key, bytes(corrupted_ct))

    # 4. Trigger verification via POST /versions/{id}/verify
    verify_resp = await client.post(
        f"/api/v1/versions/{version_id}/verify",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert verify_resp.status_code == 200
    res_data = verify_resp.json()
    assert res_data["is_valid"] is False
    assert res_data["failure_stage"] == "CIPHERTEXT_AUTH"
    assert res_data["error_code"] == "CIPHERTEXT_AUTH_FAILED"

    # 5. Check version state: automatically QUARANTINED
    v_resp = await client.get(
        f"/api/v1/versions/{version_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert v_resp.json()["state"] == "QUARANTINED"

    # 6. Attempt retrieval: BLOCKED
    get_resp = await client.get(
        f"/api/v1/versions/{version_id}/content",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert get_resp.status_code in [403, 422]
    assert "quarantined" in get_resp.json()["detail"].lower()

    # 7. Check integrity alerts: alert exists with status OPEN
    alerts_resp = await client.get(
        f"/api/v1/cases/{case_id}/alerts",
        headers={"Authorization": f"Bearer {token}"},
    )
    alerts = alerts_resp.json()
    open_alerts = [a for a in alerts if a["version_id"] == version_id]
    assert len(open_alerts) > 0
    assert open_alerts[0]["status"] == "OPEN"
