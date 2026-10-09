"""SQLAlchemy Database Models for EvidenceShield AI.

Preserves case_id, document_id, version_id, state, digest, and monotonic audit sequence.
"""

from datetime import datetime, timezone
import uuid
from typing import List, Optional

from sqlalchemy import (
    Column,
    String,
    Integer,
    BigInteger,
    Boolean,
    Text,
    DateTime,
    ForeignKey,
    UniqueConstraint,
    Index,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


def utc_now():
    return datetime.now(timezone.utc)


class Case(Base):
    __tablename__ = "cases"

    case_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_number = Column(String(64), unique=True, nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    agency = Column(String(128), nullable=False, index=True)
    lead_investigator_id = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    status = Column(String(32), default="ACTIVE", nullable=False)

    documents = relationship("Document", back_populates="case", cascade="all, delete-orphan")
    assignments = relationship("CaseAssignment", back_populates="case", cascade="all, delete-orphan")


class CaseAssignment(Base):
    __tablename__ = "case_assignments"

    assignment_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String(36), ForeignKey("cases.case_id"), nullable=False, index=True)
    principal_id = Column(String(64), nullable=False, index=True)
    role = Column(String(32), nullable=False)  # POLICE, FORENSIC_LAB, PROSECUTOR, etc.
    agency = Column(String(128), nullable=False)
    assigned_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    case = relationship("Case", back_populates="assignments")

    __table_args__ = (
        UniqueConstraint("case_id", "principal_id", name="uq_case_principal"),
    )


class Document(Base):
    __tablename__ = "documents"

    document_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String(36), ForeignKey("cases.case_id"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    classification = Column(String(32), default="INTERNAL", nullable=False)  # INTERNAL, SENSITIVE, RESTRICTED
    created_by_id = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    case = relationship("Case", back_populates="documents")
    versions = relationship("DocumentVersion", back_populates="document", cascade="all, delete-orphan")
    grants = relationship("DocumentGrant", back_populates="document", cascade="all, delete-orphan")


class DocumentVersion(Base):
    __tablename__ = "document_versions"

    version_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    document_id = Column(String(36), ForeignKey("documents.document_id"), nullable=False, index=True)
    case_id = Column(String(36), ForeignKey("cases.case_id"), nullable=False, index=True)
    version_number = Column(Integer, nullable=False, default=1)
    state = Column(String(32), default="INGESTING", nullable=False, index=True)
    # Lifecycle states: INGESTING, READY_PENDING_ANCHOR, VERIFIED_ANCHORED, QUARANTINED, FAILED

    digest = Column(String(64), nullable=False, index=True)  # Plaintext SHA-256
    size_bytes = Column(BigInteger, nullable=False)
    mime_type = Column(String(128), nullable=False)
    file_name = Column(String(255), nullable=False)
    page_count = Column(Integer, nullable=True)

    # Storage references & wrapped key metadata
    object_key = Column(String(512), nullable=False)
    nonce = Column(String(64), nullable=False)
    tag = Column(String(64), nullable=False)
    wrapped_key = Column(Text, nullable=False)
    key_id = Column(String(128), nullable=False)
    aad_json = Column(Text, nullable=False)
    signed_baseline = Column(Text, nullable=True)

    declared_capture_time = Column(DateTime(timezone=True), nullable=True)
    declared_timezone = Column(String(64), nullable=True)
    created_by_id = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    sealed_at = Column(DateTime(timezone=True), nullable=True)
    quarantine_reason = Column(Text, nullable=True)

    document = relationship("Document", back_populates="versions")

    __table_args__ = (
        UniqueConstraint("document_id", "version_number", name="uq_doc_version"),
    )


class DocumentGrant(Base):
    __tablename__ = "document_grants"

    grant_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    document_id = Column(String(36), ForeignKey("documents.document_id"), nullable=False, index=True)
    case_id = Column(String(36), ForeignKey("cases.case_id"), nullable=False, index=True)
    principal_id = Column(String(64), nullable=False, index=True)
    granted_by_id = Column(String(64), nullable=False)
    actions = Column(Text, nullable=False)  # JSON-encoded array: ["document:read", "document:download"]
    expires_at = Column(DateTime(timezone=True), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    document = relationship("Document", back_populates="grants")


class CustodyTransfer(Base):
    __tablename__ = "custody_transfers"

    transfer_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    version_id = Column(String(36), ForeignKey("document_versions.version_id"), nullable=False, index=True)
    case_id = Column(String(36), ForeignKey("cases.case_id"), nullable=False, index=True)
    sender_id = Column(String(64), nullable=False)
    sender_agency = Column(String(128), nullable=False)
    recipient_id = Column(String(64), nullable=False, index=True)
    recipient_agency = Column(String(128), nullable=False)
    reason = Column(Text, nullable=False)
    state = Column(String(32), default="PENDING", nullable=False)  # PENDING, ACCEPTED, REJECTED, CANCELLED

    initiated_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    responded_at = Column(DateTime(timezone=True), nullable=True)
    response_notes = Column(Text, nullable=True)

    sender_receipt_sig = Column(Text, nullable=True)
    recipient_receipt_sig = Column(Text, nullable=True)


class DerivativeLineage(Base):
    __tablename__ = "derivative_lineage"

    lineage_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    parent_version_id = Column(String(36), ForeignKey("document_versions.version_id"), nullable=False, index=True)
    child_version_id = Column(String(36), ForeignKey("document_versions.version_id"), nullable=False, index=True)
    operation = Column(String(64), nullable=False)  # e.g., OCR_EXTRACTION, REDACTION, FORENSIC_DENOISE
    tool_name = Column(String(128), nullable=False)
    tool_version = Column(String(64), nullable=False)
    operator_id = Column(String(64), nullable=False)
    input_digest = Column(String(64), nullable=False)
    output_digest = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    # Monotonic committed sequence allocated under table/ledger lock
    sequence_id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String(36), default=lambda: str(uuid.uuid4()), nullable=False, unique=True)
    event_type = Column(String(64), nullable=False, index=True)
    actor_id = Column(String(64), nullable=False, index=True)
    actor_role = Column(String(32), nullable=False)
    actor_agency = Column(String(128), nullable=False)
    resource_type = Column(String(32), nullable=False)
    resource_id = Column(String(64), nullable=False, index=True)
    payload_digest = Column(String(64), nullable=False)
    canonical_payload = Column(Text, nullable=False)
    prev_event_hash = Column(String(64), nullable=False)
    event_hash = Column(String(64), nullable=False, index=True)
    signature = Column(Text, nullable=False)
    signing_key_id = Column(String(64), nullable=False)
    committed_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)


class MerkleCheckpoint(Base):
    __tablename__ = "merkle_checkpoints"

    checkpoint_id = Column(String(64), primary_key=True)
    tree_size = Column(BigInteger, nullable=False)
    root_hash = Column(String(64), nullable=False, index=True)
    prev_root_hash = Column(String(64), nullable=False)
    signature = Column(Text, nullable=False)
    signing_key_id = Column(String(64), nullable=False)
    status = Column(String(32), default="PENDING", nullable=False)  # PENDING, SUBMITTED, CONFIRMED, FAILED
    tx_hash = Column(String(66), nullable=True)
    block_number = Column(BigInteger, nullable=True)
    chain_receipt_json = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    confirmed_at = Column(DateTime(timezone=True), nullable=True)


class IntegrityAlert(Base):
    __tablename__ = "integrity_alerts"

    alert_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    version_id = Column(String(36), ForeignKey("document_versions.version_id"), nullable=False, index=True)
    case_id = Column(String(36), ForeignKey("cases.case_id"), nullable=False, index=True)
    alert_type = Column(String(64), nullable=False)
    failure_stage = Column(String(64), nullable=False)
    error_details = Column(Text, nullable=False)
    status = Column(String(32), default="OPEN", nullable=False)
    # OPEN, INVESTIGATING, CONFIRMED_TAMPERED, DISMISSED_FALSE_POSITIVE
    assigned_reviewer_id = Column(String(64), nullable=True)
    disposition_notes = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    resolved_at = Column(DateTime(timezone=True), nullable=True)


class AnalysisArtifact(Base):
    __tablename__ = "analysis_artifacts"

    artifact_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    version_id = Column(String(36), ForeignKey("document_versions.version_id"), nullable=False, index=True)
    case_id = Column(String(36), ForeignKey("cases.case_id"), nullable=False, index=True)
    artifact_type = Column(String(64), nullable=False)  # OCR_TEXT, SUMMARY, TIMELINE, INCONSISTENCY
    encrypted_content = Column(Text, nullable=False)
    nonce = Column(String(64), nullable=False)
    tag = Column(String(64), nullable=False)
    model_name = Column(String(64), nullable=True)
    prompt_version = Column(String(32), nullable=True)
    source_references_json = Column(Text, nullable=True)  # JSON array of [version_id, page, span, quote]
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)


class InconsistencyReview(Base):
    __tablename__ = "inconsistency_reviews"

    review_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String(36), ForeignKey("cases.case_id"), nullable=False, index=True)
    finding_type = Column(String(64), nullable=False)  # e.g., DATE_DISCREPANCY, VEHICLE_NUMBER_MISMATCH
    description = Column(Text, nullable=False)
    source_spans_json = Column(Text, nullable=False)
    human_disposition = Column(String(32), default="PENDING", nullable=False)  # PENDING, CONFIRMED, DISMISSED
    reviewer_id = Column(String(64), nullable=True)
    rationale = Column(Text, nullable=True)
    reviewed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)


class DurableJob(Base):
    __tablename__ = "durable_jobs"

    job_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    job_type = Column(String(64), nullable=False, index=True)
    status = Column(String(32), default="PENDING", nullable=False, index=True)
    payload_json = Column(Text, nullable=False)
    retry_count = Column(Integer, default=0, nullable=False)
    max_retries = Column(Integer, default=5, nullable=False)
    lock_token = Column(String(64), nullable=True)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    last_error = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)


class TransactionalOutbox(Base):
    __tablename__ = "transactional_outbox"

    outbox_id = Column(Integer, primary_key=True, autoincrement=True)
    event_type = Column(String(64), nullable=False, index=True)
    payload_json = Column(Text, nullable=False)
    processed = Column(Boolean, default=False, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)


class UploadSession(Base):
    __tablename__ = "upload_sessions"

    session_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String(36), ForeignKey("cases.case_id"), nullable=False)
    created_by_id = Column(String(64), nullable=False)
    file_name = Column(String(255), nullable=False)
    mime_type = Column(String(128), nullable=False)
    size_bytes = Column(BigInteger, nullable=False)
    classification = Column(String(32), default="INTERNAL", nullable=False)
    declared_capture_time = Column(DateTime(timezone=True), nullable=True)
    declared_timezone = Column(String(64), nullable=True)
    state = Column(String(32), default="PENDING", nullable=False)  # PENDING, PROCESSING, COMPLETED, FAILED
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
