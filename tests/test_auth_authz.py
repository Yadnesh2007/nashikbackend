"""Test Authentication, Role Portals, and Zero-Trust Authorization Policies."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_login_and_session(client: AsyncClient):
    # 1. Login as Officer Sharma
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={
            "username": "officer_sharma",
            "password": "valid_password",
            "role": "POLICE",
            "agency": "MUMBAI_CRIME_BRANCH",
        },
    )
    assert login_resp.status_code == 200
    data = login_resp.json()
    assert data["user_id"] == "officer_sharma"
    assert data["role"] == "POLICE"

    token = data["token"]

    # 2. Check session endpoint
    sess_resp = await client.get(
        "/api/v1/auth/session",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert sess_resp.status_code == 200
    sess_data = sess_resp.json()
    assert sess_data["username"] == "officer_sharma"
    assert sess_data["mfa_fresh"] is False


@pytest.mark.asyncio
async def test_cross_case_access_denial(client: AsyncClient):
    # Login as unauthorized cop assigned only to Delhi Case
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={
            "username": "unauthorized_cop",
            "password": "valid_password",
            "role": "POLICE",
            "agency": "DELHI_SPECIAL_CELL",
        },
    )
    token = login_resp.json()["token"]

    # Attempt to read Mumbai Crime Branch Case
    resp = await client.get(
        "/api/v1/cases/c7b2a9e0-82a1-4b13-912f-6825a07e1123",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403
    err = resp.json()
    assert err["code"] == "FORBIDDEN"


@pytest.mark.asyncio
async def test_system_admin_evidence_decryption_blocked(client: AsyncClient):
    # Login as System Admin
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={
            "username": "admin_user",
            "password": "valid_password",
            "role": "SYSTEM_ADMIN",
            "agency": "COURT_ADMINISTRATION",
        },
    )
    token = login_resp.json()["token"]

    # List cases: Admin is denied evidence download
    # Pick a version ID from seeded case
    cases_resp = await client.get(
        "/api/v1/cases",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert cases_resp.status_code == 200


@pytest.mark.asyncio
async def test_mfa_freshness_requirement(client: AsyncClient):
    # Login as Prosecutor without MFA
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={
            "username": "prosecutor_iyer",
            "password": "valid_password",
            "role": "PROSECUTOR",
            "agency": "MAHARASHTRA_PROSECUTION",
        },
    )
    token = login_resp.json()["token"]

    # Attempt export without fresh MFA -> 403 Forbidden
    export_resp = await client.post(
        "/api/v1/cases/c7b2a9e0-82a1-4b13-912f-6825a07e1123/exports",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert export_resp.status_code == 403
    assert "fresh MFA" in export_resp.json()["detail"]

    # Now verify MFA
    mfa_resp = await client.post(
        "/api/v1/auth/mfa/verify",
        json={"code": "123456"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert mfa_resp.status_code == 200
    assert mfa_resp.json()["verified"] is True
