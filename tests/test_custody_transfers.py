"""Test Custody Transfers, Recipient Rules, and Gap Explanations."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_custody_transfer_workflow(client: AsyncClient):
    # 1. Police logs in
    p_login = await client.post(
        "/api/v1/auth/login",
        json={"username": "officer_sharma", "password": "pw", "role": "POLICE", "agency": "MUMBAI_CRIME_BRANCH"},
    )
    p_token = p_login.json()["token"]

    # Pick version from case detail
    case_resp = await client.get(
        "/api/v1/cases/c7b2a9e0-82a1-4b13-912f-6825a07e1123",
        headers={"Authorization": f"Bearer {p_token}"},
    )
    docs = case_resp.json()["documents"]
    version_id = docs[0]["current_version_id"]

    # 2. Initiate custody transfer to Forensic Lab
    t_resp = await client.post(
        f"/api/v1/versions/{version_id}/transfers",
        json={
            "recipient_id": "examiner_patel",
            "recipient_agency": "STATE_FORENSIC_SCI_LAB",
            "reason": "Ballistic and vehicle telemetry examination",
        },
        headers={"Authorization": f"Bearer {p_token}"},
    )
    assert t_resp.status_code == 201
    transfer_id = t_resp.json()["transfer_id"]
    assert t_resp.json()["state"] == "PENDING"
    assert len(t_resp.json()["sender_receipt_sig"]) > 0

    # 3. Check readiness checklist: Unacknowledged transfer is detected as custody gap
    r_resp = await client.get(
        "/api/v1/cases/c7b2a9e0-82a1-4b13-912f-6825a07e1123/readiness",
        headers={"Authorization": f"Bearer {p_token}"},
    )
    readiness = r_resp.json()
    assert readiness["is_ready"] is False
    assert any("custody" in o.lower() for o in readiness["omissions"])

    # 4. Unauthorized user (Prosecutor or other cop) cannot accept
    prosecutor_login = await client.post(
        "/api/v1/auth/login",
        json={"username": "prosecutor_iyer", "password": "pw", "role": "PROSECUTOR", "agency": "MAHARASHTRA_PROSECUTION"},
    )
    prosecutor_token = prosecutor_login.json()["token"]

    bad_accept = await client.post(
        f"/api/v1/transfers/{transfer_id}/accept",
        json={"notes": "Wrong user trying to accept"},
        headers={"Authorization": f"Bearer {prosecutor_token}"},
    )
    assert bad_accept.status_code == 403

    # 5. Designated Recipient (Examiner Patel) accepts
    lab_login = await client.post(
        "/api/v1/auth/login",
        json={"username": "examiner_patel", "password": "pw", "role": "FORENSIC_LAB", "agency": "STATE_FORENSIC_SCI_LAB"},
    )
    lab_token = lab_login.json()["token"]

    accept_resp = await client.post(
        f"/api/v1/transfers/{transfer_id}/accept",
        json={"notes": "Received sealed item at Forensic Lab physics division."},
        headers={"Authorization": f"Bearer {lab_token}"},
    )
    assert accept_resp.status_code == 200
    assert accept_resp.json()["state"] == "ACCEPTED"
    assert len(accept_resp.json()["recipient_receipt_sig"]) > 0
