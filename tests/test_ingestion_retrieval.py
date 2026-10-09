"""Test Ingestion, Bounds Validation, Encryption, and Verified Retrieval."""

import hashlib
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_upload_and_verified_retrieval(client: AsyncClient):
    # 1. Login as Officer Sharma
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"username": "officer_sharma", "password": "pw", "role": "POLICE", "agency": "MUMBAI_CRIME_BRANCH"},
    )
    token = login_resp.json()["token"]
    case_id = "c7b2a9e0-82a1-4b13-912f-6825a07e1123"

    # 2. Create upload session
    raw_content = b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n"
    expected_digest = hashlib.sha256(raw_content).hexdigest()

    sess_resp = await client.post(
        f"/api/v1/cases/{case_id}/upload-sessions",
        json={
            "file_name": "additional_statement.pdf",
            "mime_type": "application/pdf",
            "size_bytes": len(raw_content),
            "classification": "SENSITIVE",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert sess_resp.status_code == 201
    session_id = sess_resp.json()["session_id"]

    # 3. Stream upload content
    upload_resp = await client.put(
        f"/api/v1/upload-sessions/{session_id}/content",
        content=raw_content,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/octet-stream"},
    )
    assert upload_resp.status_code == 200
    v_data = upload_resp.json()
    version_id = v_data["version_id"]
    assert v_data["digest"] == expected_digest
    assert v_data["state"] == "READY_PENDING_ANCHOR"

    # 4. Verified retrieval
    get_resp = await client.get(
        f"/api/v1/versions/{version_id}/content",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert get_resp.status_code == 200
    assert get_resp.content == raw_content
    # Invariant: Cache-Control must be no-store
    assert "no-store" in get_resp.headers.get("Cache-Control", "")


@pytest.mark.asyncio
async def test_oversize_upload_rejected(client: AsyncClient):
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"username": "officer_sharma", "password": "pw", "role": "POLICE", "agency": "MUMBAI_CRIME_BRANCH"},
    )
    token = login_resp.json()["token"]
    case_id = "c7b2a9e0-82a1-4b13-912f-6825a07e1123"

    # Attempt to create upload session > 25 MB
    sess_resp = await client.post(
        f"/api/v1/cases/{case_id}/upload-sessions",
        json={
            "file_name": "huge_file.pdf",
            "mime_type": "application/pdf",
            "size_bytes": 30 * 1024 * 1024,  # 30 MB
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert sess_resp.status_code == 413
