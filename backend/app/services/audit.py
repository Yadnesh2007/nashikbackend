"""Monotonic Chronological Audit Ledger Service with Ed25519 Signatures."""

from datetime import datetime, timezone
import hashlib
import json
import uuid
from typing import Optional, Dict, Any, List

from sqlalchemy import select, func, desc, text
from sqlalchemy.ext.asyncio import AsyncSession

from evidenceshield_crypto import (
    canonicalize_json,
    sign_canonical_payload,
    generate_signing_keypair,
)
from ..models.entities import AuditEvent

# Platform signing keypair initialized for runtime
PLATFORM_PRIV_KEY, PLATFORM_PUB_KEY = generate_signing_keypair()
PLATFORM_KEY_ID = "key_ed25519_2026_01"


class AuditLedgerService:
    """Manages append-only monotonic audit ledger with hash chaining."""

    def __init__(
        self,
        priv_key: bytes = PLATFORM_PRIV_KEY,
        pub_key: bytes = PLATFORM_PUB_KEY,
        key_id: str = PLATFORM_KEY_ID,
    ):
        self.priv_key = priv_key
        self.pub_key = pub_key
        self.key_id = key_id

    async def get_latest_event_hash(self, session: AsyncSession) -> str:
        """Retrieves latest event hash for chaining, or returns 64 zeroes for genesis."""
        stmt = select(AuditEvent.event_hash).order_by(desc(AuditEvent.sequence_id)).limit(1)
        res = await session.execute(stmt)
        row = res.scalar_one_or_none()
        if row:
            return row
        return "0" * 64

    async def append_event(
        self,
        session: AsyncSession,
        event_type: str,
        actor_id: str,
        actor_role: str,
        actor_agency: str,
        resource_type: str,
        resource_id: str,
        payload: Dict[str, Any],
    ) -> AuditEvent:
        """Appends a new event under monotonic sequence lock.

        In PostgreSQL, uses table lock or advisory lock to ensure sequence integrity.
        """
        # Advisory transaction lock for ledger concurrency control
        try:
            await session.execute(text("SELECT pg_advisory_xact_lock(42001);"))
        except Exception:
            pass

        prev_hash = await self.get_latest_event_hash(session)
        now_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        event_id = str(uuid.uuid4())

        # Canonicalize payload to get payload_digest
        canonical_payload_bytes = canonicalize_json(payload)
        payload_digest = hashlib.sha256(canonical_payload_bytes).hexdigest()

        # Build full canonical event data structure
        event_data = {
            "actor_agency": actor_agency,
            "actor_id": actor_id,
            "actor_role": actor_role,
            "committed_at": now_utc,
            "event_id": event_id,
            "event_type": event_type,
            "payload_digest": payload_digest,
            "prev_event_hash": prev_hash,
            "resource_id": resource_id,
            "resource_type": resource_type,
        }

        # Sign canonical event with platform Ed25519 key
        signature_b64, event_hash = sign_canonical_payload(event_data, self.priv_key)

        audit_record = AuditEvent(
            event_id=event_id,
            event_type=event_type,
            actor_id=actor_id,
            actor_role=actor_role,
            actor_agency=actor_agency,
            resource_type=resource_type,
            resource_id=resource_id,
            payload_digest=payload_digest,
            canonical_payload=json.dumps(payload),
            prev_event_hash=prev_hash,
            event_hash=event_hash,
            signature=signature_b64,
            signing_key_id=self.key_id,
            committed_at=datetime.now(timezone.utc),
        )

        session.add(audit_record)
        await session.flush()
        return audit_record


audit_service = AuditLedgerService()
