"""Initial schema for EvidenceShield AI.

Revision ID: 001_initial_schema
Revises: 
Create Date: 2026-10-09 16:30:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '001_initial_schema'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Cases
    op.create_table(
        'cases',
        sa.Column('case_id', sa.String(length=36), primary_key=True),
        sa.Column('case_number', sa.String(length=64), nullable=False, unique=True),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('agency', sa.String(length=128), nullable=False),
        sa.Column('lead_investigator_id', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='ACTIVE'),
    )

    # 2. Case Assignments
    op.create_table(
        'case_assignments',
        sa.Column('assignment_id', sa.String(length=36), primary_key=True),
        sa.Column('case_id', sa.String(length=36), sa.ForeignKey('cases.case_id'), nullable=False),
        sa.Column('principal_id', sa.String(length=64), nullable=False),
        sa.Column('role', sa.String(length=32), nullable=False),
        sa.Column('agency', sa.String(length=128), nullable=False),
        sa.Column('assigned_at', sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint('case_id', 'principal_id', name='uq_case_principal'),
    )

    # 3. Documents
    op.create_table(
        'documents',
        sa.Column('document_id', sa.String(length=36), primary_key=True),
        sa.Column('case_id', sa.String(length=36), sa.ForeignKey('cases.case_id'), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('classification', sa.String(length=32), nullable=False, server_default='INTERNAL'),
        sa.Column('created_by_id', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )

    # 4. Document Versions
    op.create_table(
        'document_versions',
        sa.Column('version_id', sa.String(length=36), primary_key=True),
        sa.Column('document_id', sa.String(length=36), sa.ForeignKey('documents.document_id'), nullable=False),
        sa.Column('case_id', sa.String(length=36), sa.ForeignKey('cases.case_id'), nullable=False),
        sa.Column('version_number', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('state', sa.String(length=32), nullable=False, server_default='INGESTING'),
        sa.Column('digest', sa.String(length=64), nullable=False),
        sa.Column('size_bytes', sa.BigInteger(), nullable=False),
        sa.Column('mime_type', sa.String(length=128), nullable=False),
        sa.Column('file_name', sa.String(length=255), nullable=False),
        sa.Column('page_count', sa.Integer(), nullable=True),
        sa.Column('object_key', sa.String(length=512), nullable=False),
        sa.Column('nonce', sa.String(length=64), nullable=False),
        sa.Column('tag', sa.String(length=64), nullable=False),
        sa.Column('wrapped_key', sa.Text(), nullable=False),
        sa.Column('key_id', sa.String(length=128), nullable=False),
        sa.Column('aad_json', sa.Text(), nullable=False),
        sa.Column('signed_baseline', sa.Text(), nullable=True),
        sa.Column('declared_capture_time', sa.DateTime(timezone=True), nullable=True),
        sa.Column('declared_timezone', sa.String(length=64), nullable=True),
        sa.Column('created_by_id', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('sealed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('quarantine_reason', sa.Text(), nullable=True),
        sa.UniqueConstraint('document_id', 'version_number', name='uq_doc_version'),
    )

    # 5. Document Grants
    op.create_table(
        'document_grants',
        sa.Column('grant_id', sa.String(length=36), primary_key=True),
        sa.Column('document_id', sa.String(length=36), sa.ForeignKey('documents.document_id'), nullable=False),
        sa.Column('case_id', sa.String(length=36), sa.ForeignKey('cases.case_id'), nullable=False),
        sa.Column('principal_id', sa.String(length=64), nullable=False),
        sa.Column('granted_by_id', sa.String(length=64), nullable=False),
        sa.Column('actions', sa.Text(), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )

    # 6. Custody Transfers
    op.create_table(
        'custody_transfers',
        sa.Column('transfer_id', sa.String(length=36), primary_key=True),
        sa.Column('version_id', sa.String(length=36), sa.ForeignKey('document_versions.version_id'), nullable=False),
        sa.Column('case_id', sa.String(length=36), sa.ForeignKey('cases.case_id'), nullable=False),
        sa.Column('sender_id', sa.String(length=64), nullable=False),
        sa.Column('sender_agency', sa.String(length=128), nullable=False),
        sa.Column('recipient_id', sa.String(length=64), nullable=False),
        sa.Column('recipient_agency', sa.String(length=128), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('state', sa.String(length=32), nullable=False, server_default='PENDING'),
        sa.Column('initiated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('responded_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('response_notes', sa.Text(), nullable=True),
        sa.Column('sender_receipt_sig', sa.Text(), nullable=True),
        sa.Column('recipient_receipt_sig', sa.Text(), nullable=True),
    )

    # 7. Derivative Lineage
    op.create_table(
        'derivative_lineage',
        sa.Column('lineage_id', sa.String(length=36), primary_key=True),
        sa.Column('parent_version_id', sa.String(length=36), sa.ForeignKey('document_versions.version_id'), nullable=False),
        sa.Column('child_version_id', sa.String(length=36), sa.ForeignKey('document_versions.version_id'), nullable=False),
        sa.Column('operation', sa.String(length=64), nullable=False),
        sa.Column('tool_name', sa.String(length=128), nullable=False),
        sa.Column('tool_version', sa.String(length=64), nullable=False),
        sa.Column('operator_id', sa.String(length=64), nullable=False),
        sa.Column('input_digest', sa.String(length=64), nullable=False),
        sa.Column('output_digest', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )

    # 8. Audit Events (Monotonic committed ledger)
    op.create_table(
        'audit_events',
        sa.Column('sequence_id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('event_id', sa.String(length=36), nullable=False, unique=True),
        sa.Column('event_type', sa.String(length=64), nullable=False),
        sa.Column('actor_id', sa.String(length=64), nullable=False),
        sa.Column('actor_role', sa.String(length=32), nullable=False),
        sa.Column('actor_agency', sa.String(length=128), nullable=False),
        sa.Column('resource_type', sa.String(length=32), nullable=False),
        sa.Column('resource_id', sa.String(length=64), nullable=False),
        sa.Column('payload_digest', sa.String(length=64), nullable=False),
        sa.Column('canonical_payload', sa.Text(), nullable=False),
        sa.Column('prev_event_hash', sa.String(length=64), nullable=False),
        sa.Column('event_hash', sa.String(length=64), nullable=False),
        sa.Column('signature', sa.Text(), nullable=False),
        sa.Column('signing_key_id', sa.String(length=64), nullable=False),
        sa.Column('committed_at', sa.DateTime(timezone=True), nullable=False),
    )

    # 9. Merkle Checkpoints
    op.create_table(
        'merkle_checkpoints',
        sa.Column('checkpoint_id', sa.String(length=64), primary_key=True),
        sa.Column('tree_size', sa.BigInteger(), nullable=False),
        sa.Column('root_hash', sa.String(length=64), nullable=False),
        sa.Column('prev_root_hash', sa.String(length=64), nullable=False),
        sa.Column('signature', sa.Text(), nullable=False),
        sa.Column('signing_key_id', sa.String(length=64), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='PENDING'),
        sa.Column('tx_hash', sa.String(length=66), nullable=True),
        sa.Column('block_number', sa.BigInteger(), nullable=True),
        sa.Column('chain_receipt_json', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('confirmed_at', sa.DateTime(timezone=True), nullable=True),
    )

    # 10. Integrity Alerts
    op.create_table(
        'integrity_alerts',
        sa.Column('alert_id', sa.String(length=36), primary_key=True),
        sa.Column('version_id', sa.String(length=36), sa.ForeignKey('document_versions.version_id'), nullable=False),
        sa.Column('case_id', sa.String(length=36), sa.ForeignKey('cases.case_id'), nullable=False),
        sa.Column('alert_type', sa.String(length=64), nullable=False),
        sa.Column('failure_stage', sa.String(length=64), nullable=False),
        sa.Column('error_details', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='OPEN'),
        sa.Column('assigned_reviewer_id', sa.String(length=64), nullable=True),
        sa.Column('disposition_notes', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
    )

    # 11. Analysis Artifacts
    op.create_table(
        'analysis_artifacts',
        sa.Column('artifact_id', sa.String(length=36), primary_key=True),
        sa.Column('version_id', sa.String(length=36), sa.ForeignKey('document_versions.version_id'), nullable=False),
        sa.Column('case_id', sa.String(length=36), sa.ForeignKey('cases.case_id'), nullable=False),
        sa.Column('artifact_type', sa.String(length=64), nullable=False),
        sa.Column('encrypted_content', sa.Text(), nullable=False),
        sa.Column('nonce', sa.String(length=64), nullable=False),
        sa.Column('tag', sa.String(length=64), nullable=False),
        sa.Column('model_name', sa.String(length=64), nullable=True),
        sa.Column('prompt_version', sa.String(length=32), nullable=True),
        sa.Column('source_references_json', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )

    # 12. Inconsistency Reviews
    op.create_table(
        'inconsistency_reviews',
        sa.Column('review_id', sa.String(length=36), primary_key=True),
        sa.Column('case_id', sa.String(length=36), sa.ForeignKey('cases.case_id'), nullable=False),
        sa.Column('finding_type', sa.String(length=64), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('source_spans_json', sa.Text(), nullable=False),
        sa.Column('human_disposition', sa.String(length=32), nullable=False, server_default='PENDING'),
        sa.Column('reviewer_id', sa.String(length=64), nullable=True),
        sa.Column('rationale', sa.Text(), nullable=True),
        sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )

    # 13. Durable Jobs & Outbox
    op.create_table(
        'durable_jobs',
        sa.Column('job_id', sa.String(length=36), primary_key=True),
        sa.Column('job_type', sa.String(length=64), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='PENDING'),
        sa.Column('payload_json', sa.Text(), nullable=False),
        sa.Column('retry_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('max_retries', sa.Integer(), nullable=False, server_default='5'),
        sa.Column('lock_token', sa.String(length=64), nullable=True),
        sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_error', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        'transactional_outbox',
        sa.Column('outbox_id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('event_type', sa.String(length=64), nullable=False),
        sa.Column('payload_json', sa.Text(), nullable=False),
        sa.Column('processed', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )

    # 14. Upload Sessions
    op.create_table(
        'upload_sessions',
        sa.Column('session_id', sa.String(length=36), primary_key=True),
        sa.Column('case_id', sa.String(length=36), sa.ForeignKey('cases.case_id'), nullable=False),
        sa.Column('created_by_id', sa.String(length=64), nullable=False),
        sa.Column('file_name', sa.String(length=255), nullable=False),
        sa.Column('mime_type', sa.String(length=128), nullable=False),
        sa.Column('size_bytes', sa.BigInteger(), nullable=False),
        sa.Column('classification', sa.String(length=32), nullable=False, server_default='INTERNAL'),
        sa.Column('declared_capture_time', sa.DateTime(timezone=True), nullable=True),
        sa.Column('declared_timezone', sa.String(length=64), nullable=True),
        sa.Column('state', sa.String(length=32), nullable=False, server_default='PENDING'),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table('upload_sessions')
    op.drop_table('transactional_outbox')
    op.drop_table('durable_jobs')
    op.drop_table('inconsistency_reviews')
    op.drop_table('analysis_artifacts')
    op.drop_table('integrity_alerts')
    op.drop_table('merkle_checkpoints')
    op.drop_table('audit_events')
    op.drop_table('derivative_lineage')
    op.drop_table('custody_transfers')
    op.drop_table('document_grants')
    op.drop_table('document_versions')
    op.drop_table('documents')
    op.drop_table('case_assignments')
    op.drop_table('cases')
