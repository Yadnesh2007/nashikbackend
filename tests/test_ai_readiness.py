"""Test AI Cited Summaries, Inconsistencies, and Readiness Preflight."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_ai_cited_summary_and_inconsistencies(client: AsyncClient):
    # 1. Login as Prosecutor
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"username": "prosecutor_iyer", "password": "pw", "role": "PROSECUTOR", "agency": "MAHARASHTRA_PROSECUTION"},
    )
    token = login_resp.json()["token"]
    case_id = "c7b2a9e0-82a1-4b13-912f-6825a07e1123"

    case_resp = await client.get(
        f"/api/v1/cases/{case_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    v_ids = [d["current_version_id"] for d in case_resp.json()["documents"] if d["current_version_id"]]

    # 2. Trigger AI Summary
    summary_resp = await client.post(
        f"/api/v1/cases/{case_id}/analysis",
        json={
            "analysis_type": "SUMMARY",
            "document_version_ids": v_ids,
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert summary_resp.status_code == 202
    res = summary_resp.json()["result"]
    assert len(res["summary"]) > 0
    # Enforce exact citation structure
    assert len(res["citations"]) > 0
    citation = res["citations"][0]
    assert "version_id" in citation
    assert "page" in citation
    assert "quote" in citation

    # 3. Trigger Inconsistency Finder
    incon_resp = await client.post(
        f"/api/v1/cases/{case_id}/analysis",
        json={
            "analysis_type": "INCONSISTENCY",
            "document_version_ids": v_ids,
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert incon_resp.status_code == 202
    findings = incon_resp.json().get("findings", [])
    if findings:
        review_id = findings[0]["review_id"]
        # Human confirms finding
        conf_resp = await client.post(
            f"/api/v1/analysis/inconsistencies/{review_id}/review",
            json={"human_disposition": "CONFIRMED", "rationale": "Verified discrepancy against FSL log."},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert conf_resp.status_code == 200
        assert conf_resp.json()["human_disposition"] == "CONFIRMED"
