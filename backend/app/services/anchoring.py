"""Cumulative Merkle Tree Checkpoint and Blockchain Anchoring Service."""

from datetime import datetime, timezone
import json
from typing import Optional, Dict, Any, List

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from evidenceshield_crypto import (
    MerkleTree,
    sign_canonical_payload,
)
from evidenceshield_crypto.anchor import AnvilAnchorClient
from ..models.entities import AuditEvent, MerkleCheckpoint, DocumentVersion
from ..core.config import settings
from .audit import PLATFORM_PRIV_KEY, PLATFORM_KEY_ID


class AnchoringService:
    """Orchestrates Merkle checkpoint generation and Anvil blockchain anchoring."""

    def __init__(self):
        self.anchor_client = AnvilAnchorClient(
            rpc_url=settings.anvil_rpc_url,
            contract_address=settings.anchor_contract_address,
            private_key=settings.anchor_publisher_private_key,
        )

    async def create_and_publish_checkpoint(
        self,
        session: AsyncSession,
        ledger_id: str = "evidenceshield_main_ledger",
    ) -> MerkleCheckpoint:
        """Gathers committed audit events, computes Merkle root, and publishes anchor."""
        # 1. Fetch all audit events in monotonic sequence order
        stmt = select(AuditEvent).order_by(AuditEvent.sequence_id.asc())
        res = await session.execute(stmt)
        events = res.scalars().all()

        if not events:
            raise ValueError("No audit events to anchor.")

        tree_size = len(events)
        # Leaves are the event_hash bytes
        leaves = [bytes.fromhex(ev.event_hash) for ev in events]
        tree = MerkleTree(leaves)
        root_hash = tree.get_root_hash()

        # Fetch previous checkpoint for continuity
        prev_stmt = select(MerkleCheckpoint).order_by(MerkleCheckpoint.tree_size.desc()).limit(1)
        prev_res = await session.execute(prev_stmt)
        prev_cp = prev_res.scalar_one_or_none()
        prev_root_hash = prev_cp.root_hash if prev_cp else "0" * 64

        checkpoint_id = f"chk_{tree_size:08d}"

        # Sign checkpoint metadata
        cp_data = {
            "checkpoint_id": checkpoint_id,
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "ledger_id": ledger_id,
            "prev_root_hash": prev_root_hash,
            "root_hash": root_hash,
            "tree_size": tree_size,
        }
        sig_b64, _ = sign_canonical_payload(cp_data, PLATFORM_PRIV_KEY)

        checkpoint = MerkleCheckpoint(
            checkpoint_id=checkpoint_id,
            tree_size=tree_size,
            root_hash=root_hash,
            prev_root_hash=prev_root_hash,
            signature=sig_b64,
            signing_key_id=PLATFORM_KEY_ID,
            status="PENDING",
            created_at=datetime.now(timezone.utc),
        )
        session.add(checkpoint)
        await session.flush()

        # 2. Publish to local Anvil blockchain
        receipt = self.anchor_client.publish_checkpoint(
            ledger_id=ledger_id,
            tree_size=tree_size,
            merkle_root_hex=root_hash,
            prev_root_hex=prev_root_hash,
        )

        if receipt.get("status") == 1:
            checkpoint.status = "CONFIRMED"
            checkpoint.tx_hash = receipt.get("transaction_hash")
            checkpoint.block_number = receipt.get("block_number")
            checkpoint.chain_receipt_json = json.dumps(receipt)
            checkpoint.confirmed_at = datetime.now(timezone.utc)

            # Invariant: Transition all READY_PENDING_ANCHOR versions to VERIFIED_ANCHORED
            upd_stmt = (
                update(DocumentVersion)
                .where(DocumentVersion.state == "READY_PENDING_ANCHOR")
                .values(state="VERIFIED_ANCHORED")
            )
            await session.execute(upd_stmt)
        else:
            checkpoint.status = "FAILED"

        await session.flush()
        return checkpoint

    async def get_inclusion_proof_for_event(
        self,
        session: AsyncSession,
        sequence_id: int,
    ) -> Dict[str, Any]:
        """Generates RFC 9162 inclusion proof for event at sequence_id."""
        stmt = select(AuditEvent).order_by(AuditEvent.sequence_id.asc())
        res = await session.execute(stmt)
        events = res.scalars().all()

        leaf_index = -1
        for idx, ev in enumerate(events):
            if ev.sequence_id == sequence_id:
                leaf_index = idx
                break

        if leaf_index == -1:
            raise IndexError(f"Audit event with sequence_id {sequence_id} not found")

        leaves = [bytes.fromhex(ev.event_hash) for ev in events]
        tree = MerkleTree(leaves)
        proof = tree.get_inclusion_proof(leaf_index)
        root = tree.get_root_hash()

        # Get latest confirmed checkpoint
        cp_stmt = (
            select(MerkleCheckpoint)
            .where(MerkleCheckpoint.status == "CONFIRMED")
            .order_by(MerkleCheckpoint.tree_size.desc())
            .limit(1)
        )
        cp_res = await session.execute(cp_stmt)
        latest_cp = cp_res.scalar_one_or_none()

        return {
            "checkpoint_id": latest_cp.checkpoint_id if latest_cp else "chk_genesis",
            "tree_size": len(leaves),
            "leaf_index": leaf_index,
            "root_hash": root,
            "audit_path": proof,
        }


anchoring_service = AnchoringService()
