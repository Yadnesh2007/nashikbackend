"""Multi-stage integrity detector and verification harness."""

from dataclasses import dataclass, field
from enum import Enum
import time
from typing import Dict, Optional, Any

from .crypto import decrypt_version_bytes, CiphertextAuthError, DigestMismatchError
from .signing import verify_canonical_payload, SignatureInvalidError
from .merkle import verify_inclusion_proof, MerkleProofError


class FailureStage(str, Enum):
    NONE = "NONE"
    OBJECT_LOOKUP = "OBJECT_LOOKUP"
    CIPHERTEXT_AUTH = "CIPHERTEXT_AUTH"
    DIGEST_VERIFICATION = "DIGEST_VERIFICATION"
    SIGNATURE_VERIFICATION = "SIGNATURE_VERIFICATION"
    MERKLE_PROOF = "MERKLE_PROOF"
    BLOCKCHAIN_RECEIPT = "BLOCKCHAIN_RECEIPT"


@dataclass
class IntegrityCheckResult:
    is_valid: bool
    failure_stage: FailureStage
    error_code: str
    error_message: str
    stage_durations_ms: Dict[str, float] = field(default_factory=dict)
    decrypted_bytes: Optional[bytes] = None


def verify_evidence_integrity(
    ciphertext: Optional[bytes],
    dek: bytes,
    nonce_b64: str,
    tag_b64: str,
    case_id: str,
    document_id: str,
    version_id: str,
    format_mimetype: str,
    committed_digest: str,
    audit_event_payload: Optional[dict] = None,
    signature_b64: Optional[str] = None,
    signing_public_key: Optional[bytes] = None,
    merkle_proof: Optional[dict] = None,
    blockchain_receipt: Optional[dict] = None,
) -> IntegrityCheckResult:
    """Executes ordered, multi-stage integrity checks.

    Distinguishes ciphertext authentication failure (e.g. 1-bit corruption),
    digest mismatch, invalid signature, and invalid Merkle proof.
    """
    durations = {}

    # Stage 1: Object lookup
    t0 = time.perf_counter()
    if ciphertext is None or len(ciphertext) == 0:
        durations["object_lookup"] = (time.perf_counter() - t0) * 1000
        return IntegrityCheckResult(
            is_valid=False,
            failure_stage=FailureStage.OBJECT_LOOKUP,
            error_code="OBJECT_NOT_FOUND",
            error_message="Ciphertext binary data is missing or empty.",
            stage_durations_ms=durations,
        )
    durations["object_lookup"] = (time.perf_counter() - t0) * 1000

    # Stage 2: AES-GCM Ciphertext Authentication & Decryption
    t1 = time.perf_counter()
    decrypted_bytes = None
    try:
        decrypted_bytes = decrypt_version_bytes(
            ciphertext=ciphertext,
            dek=dek,
            nonce_b64=nonce_b64,
            tag_b64=tag_b64,
            case_id=case_id,
            document_id=document_id,
            version_id=version_id,
            format_mimetype=format_mimetype,
            expected_digest=None,  # Check digest in explicit Stage 3
        )
    except CiphertextAuthError as exc:
        durations["ciphertext_auth"] = (time.perf_counter() - t1) * 1000
        return IntegrityCheckResult(
            is_valid=False,
            failure_stage=FailureStage.CIPHERTEXT_AUTH,
            error_code="CIPHERTEXT_AUTH_FAILED",
            error_message=f"AES-256-GCM authentication failed (1-bit corruption or tag tampering): {exc}",
            stage_durations_ms=durations,
        )
    except Exception as exc:
        durations["ciphertext_auth"] = (time.perf_counter() - t1) * 1000
        return IntegrityCheckResult(
            is_valid=False,
            failure_stage=FailureStage.CIPHERTEXT_AUTH,
            error_code="CIPHERTEXT_AUTH_FAILED",
            error_message=f"Decryption error: {exc}",
            stage_durations_ms=durations,
        )
    durations["ciphertext_auth"] = (time.perf_counter() - t1) * 1000

    # Stage 3: Plaintext SHA-256 Digest Verification
    t2 = time.perf_counter()
    import hashlib
    computed_digest = hashlib.sha256(decrypted_bytes).hexdigest().lower()
    if computed_digest != committed_digest.lower():
        durations["digest_verification"] = (time.perf_counter() - t2) * 1000
        return IntegrityCheckResult(
            is_valid=False,
            failure_stage=FailureStage.DIGEST_VERIFICATION,
            error_code="DIGEST_MISMATCH",
            error_message=f"Plaintext SHA-256 digest mismatch. Computed: {computed_digest}, Committed: {committed_digest}",
            stage_durations_ms=durations,
            decrypted_bytes=decrypted_bytes,
        )
    durations["digest_verification"] = (time.perf_counter() - t2) * 1000

    # Stage 4: Audit Event Signature Verification
    t3 = time.perf_counter()
    if audit_event_payload and signature_b64 and signing_public_key:
        try:
            verify_canonical_payload(audit_event_payload, signature_b64, signing_public_key)
        except Exception as exc:
            durations["signature_verification"] = (time.perf_counter() - t3) * 1000
            return IntegrityCheckResult(
                is_valid=False,
                failure_stage=FailureStage.SIGNATURE_VERIFICATION,
                error_code="SIGNATURE_INVALID",
                error_message=f"Audit event Ed25519 signature is invalid: {exc}",
                stage_durations_ms=durations,
                decrypted_bytes=decrypted_bytes,
            )
    durations["signature_verification"] = (time.perf_counter() - t3) * 1000

    # Stage 5: Merkle Inclusion Proof Verification
    t4 = time.perf_counter()
    if merkle_proof:
        try:
            leaf_bytes = bytes.fromhex(merkle_proof.get("leaf_hash", ""))
            verify_inclusion_proof(
                leaf_bytes=leaf_bytes,
                leaf_index=merkle_proof.get("leaf_index", 0),
                tree_size=merkle_proof.get("tree_size", 0),
                expected_root_hex=merkle_proof.get("root_hash", ""),
                audit_path=merkle_proof.get("audit_path", []),
            )
        except Exception as exc:
            durations["merkle_proof"] = (time.perf_counter() - t4) * 1000
            return IntegrityCheckResult(
                is_valid=False,
                failure_stage=FailureStage.MERKLE_PROOF,
                error_code="MERKLE_PROOF_INVALID",
                error_message=f"Merkle inclusion proof failed: {exc}",
                stage_durations_ms=durations,
                decrypted_bytes=decrypted_bytes,
            )
    durations["merkle_proof"] = (time.perf_counter() - t4) * 1000

    # Stage 6: Blockchain Receipt Check
    t5 = time.perf_counter()
    if blockchain_receipt:
        status = blockchain_receipt.get("status")
        if status != 1 and status != "SUCCESS":
            durations["blockchain_receipt"] = (time.perf_counter() - t5) * 1000
            return IntegrityCheckResult(
                is_valid=False,
                failure_stage=FailureStage.BLOCKCHAIN_RECEIPT,
                error_code="CHAIN_RECEIPT_MISSING",
                error_message="Blockchain transaction receipt indicates failure or is unconfirmed.",
                stage_durations_ms=durations,
                decrypted_bytes=decrypted_bytes,
            )
    durations["blockchain_receipt"] = (time.perf_counter() - t5) * 1000

    return IntegrityCheckResult(
        is_valid=True,
        failure_stage=FailureStage.NONE,
        error_code="OK",
        error_message="All integrity verification stages passed.",
        stage_durations_ms=durations,
        decrypted_bytes=decrypted_bytes,
    )
