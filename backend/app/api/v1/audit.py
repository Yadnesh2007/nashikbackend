"""Audit Ledger and Checkpoints API Routes."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...core.database import get_db
from ...core.security import SessionUser, get_current_user
from ...models.entities import AuditEvent, MerkleCheckpoint
from ...services.anchoring import anchoring_service

router = APIRouter(prefix="/audit", tags=["Audit & Anchoring"])


@router.get("/events")
async def list_audit_events(
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    user: SessionUser = Depends(get_current_user),
):
    stmt = select(AuditEvent).order_by(AuditEvent.sequence_id.asc()).offset(offset).limit(limit)
    res = await db.execute(stmt)
    events = res.scalars().all()

    return [
        {
            "sequence_id": e.sequence_id,
            "event_id": e.event_id,
            "event_type": e.event_type,
            "actor_id": e.actor_id,
            "actor_role": e.actor_role,
            "actor_agency": e.actor_agency,
            "resource_type": e.resource_type,
            "resource_id": e.resource_id,
            "payload_digest": e.payload_digest,
            "prev_event_hash": e.prev_event_hash,
            "event_hash": e.event_hash,
            "signature": e.signature,
            "signing_key_id": e.signing_key_id,
            "committed_at": e.committed_at,
        }
        for e in events
    ]


@router.get("/checkpoints")
async def list_checkpoints(
    db: AsyncSession = Depends(get_db),
    user: SessionUser = Depends(get_current_user),
):
    stmt = select(MerkleCheckpoint).order_by(MerkleCheckpoint.tree_size.desc())
    res = await db.execute(stmt)
    cps = res.scalars().all()

    return [
        {
            "checkpoint_id": cp.checkpoint_id,
            "tree_size": cp.tree_size,
            "root_hash": cp.root_hash,
            "prev_root_hash": cp.prev_root_hash,
            "status": cp.status,
            "tx_hash": cp.tx_hash,
            "block_number": cp.block_number,
            "created_at": cp.created_at,
            "confirmed_at": cp.confirmed_at,
        }
        for cp in cps
    ]


@router.post("/checkpoints")
async def trigger_checkpoint(
    db: AsyncSession = Depends(get_db),
    user: SessionUser = Depends(get_current_user),
):
    """Manually triggers cumulative Merkle checkpoint generation and Anvil publishing."""
    cp = await anchoring_service.create_and_publish_checkpoint(db)
    await db.commit()
    return {
        "checkpoint_id": cp.checkpoint_id,
        "tree_size": cp.tree_size,
        "root_hash": cp.root_hash,
        "status": cp.status,
        "tx_hash": cp.tx_hash,
        "block_number": cp.block_number,
    }
