"""Test Audit Ordering, Monotonic Sequence, Hash Chaining, and Merkle Proofs."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_audit_event_ordering_and_hash_chain(client: AsyncClient):
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"username": "auditor_verma", "password": "pw", "role": "AUDITOR", "agency": "INDEPENDENT_JUDICIAL_AUDIT"},
    )
    token = login_resp.json()["token"]

    resp = await client.get(
        "/api/v1/audit/events?limit=50",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    events = resp.json()
    assert len(events) >= 2

    # Check monotonic sequence ordering
    for i in range(len(events) - 1):
        assert events[i]["sequence_id"] < events[i + 1]["sequence_id"]
        # Verify hash chaining
        assert events[i + 1]["prev_event_hash"] == events[i]["event_hash"]
        assert len(events[i]["signature"]) > 0


@pytest.mark.asyncio
async def test_manual_checkpoint_trigger_and_blockchain_anchor(client: AsyncClient):
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"username": "officer_sharma", "password": "pw", "role": "POLICE", "agency": "MUMBAI_CRIME_BRANCH"},
    )
    token = login_resp.json()["token"]

    # Trigger checkpoint
    cp_resp = await client.post(
        "/api/v1/audit/checkpoints",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert cp_resp.status_code == 200
    data = cp_resp.json()
    assert data["status"] == "CONFIRMED"
    assert data["tree_size"] >= 2
    assert len(data["root_hash"]) == 64
    assert data["tx_hash"].startswith("0x")
