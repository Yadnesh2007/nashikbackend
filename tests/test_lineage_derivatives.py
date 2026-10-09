"""Test Derivative Lineage, Parent Immutability, and Tool Provenance."""

import base64
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_derivative_lineage_registration(client: AsyncClient):
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"username": "examiner_patel", "password": "pw", "role": "FORENSIC_LAB", "agency": "STATE_FORENSIC_SCI_LAB"},
    )
    token = login_resp.json()["token"]

    case_resp = await client.get(
        "/api/v1/cases/c7b2a9e0-82a1-4b13-912f-6825a07e1123",
        headers={"Authorization": f"Bearer {token}"},
    )
    version_id = case_resp.json()["documents"][0]["current_version_id"]

    # Register OCR extracted text derivative
    ocr_text = b"Extracted text: Witness observed dark sedan MH-01-AB-1234 departing scene at high speed."
    b64_content = base64.b64encode(ocr_text).decode("ascii")

    deriv_resp = await client.post(
        f"/api/v1/versions/{version_id}/derivatives",
        json={
            "operation": "OCR_EXTRACTION",
            "tool_name": "tesseract",
            "tool_version": "5.3.0",
            "file_name": "statement_ocr_extracted.txt",
            "mime_type": "text/plain",
            "content_base64": b64_content,
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert deriv_resp.status_code == 201
    child_ver = deriv_resp.json()
    assert child_ver["version_number"] > 1
    assert child_ver["version_id"] != version_id

    # Verify parent version was NOT altered
    parent_resp = await client.get(
        f"/api/v1/versions/{version_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert parent_resp.json()["version_number"] == 1
