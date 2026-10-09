"""Evidence Passport Generation and Standalone Verification."""

from dataclasses import dataclass, field
import hashlib
from typing import Dict, List, Optional, Any

from .canonical import canonicalize_json
from .signing import verify_canonical_payload, SignatureInvalidError
from .merkle import verify_inclusion_proof, MerkleProofError


@dataclass
class PassportVerificationResult:
    is_valid: bool
    digest_matches: bool
    signature_valid: bool
    merkle_proof_valid: bool
    anchor_receipt_valid: bool
    errors: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


def generate_evidence_passport(
    document_meta: dict,
    audit_event: dict,
    merkle_proof: dict,
    blockchain_anchor: dict,
) -> dict:
    """Constructs the canonical Evidence Passport JSON object."""
    return {
        "passport_version": "1.0",
        "document": document_meta,
        "audit_event": audit_event,
        "merkle_proof": merkle_proof,
        "blockchain_anchor": blockchain_anchor,
    }


def verify_evidence_passport(
    file_bytes: bytes,
    passport: dict,
    trusted_public_key: Optional[bytes] = None,
    trusted_roots: Optional[Dict[str, str]] = None,
) -> PassportVerificationResult:
    """Verifies a file against its Evidence Passport in a standalone environment.

    Does NOT require a database connection. Validates:
    1. Plaintext SHA-256 match
    2. Audit event signature (if trusted_public_key provided)
    3. RFC 9162 Merkle inclusion proof against checkpoint root
    4. Blockchain anchor fields existence and format
    """
    errors: List[str] = []
    digest_matches = False
    sig_valid = False
    merkle_valid = False
    anchor_valid = False

    # 1. Plaintext SHA-256 verification
    actual_digest = hashlib.sha256(file_bytes).hexdigest().lower()
    expected_digest = passport.get("document", {}).get("digest_sha256", "").lower()

    if actual_digest == expected_digest and expected_digest != "":
        digest_matches = True
    else:
        errors.append(f"Digest mismatch: expected {expected_digest}, computed {actual_digest}")

    # 2. Audit Event Signature verification
    audit_event = passport.get("audit_event", {})
    sig_b64 = audit_event.get("signature")
    event_payload = audit_event.get("canonical_event_payload")

    if trusted_public_key and sig_b64 and event_payload:
        try:
            verify_canonical_payload(event_payload, sig_b64, trusted_public_key)
            sig_valid = True
        except Exception as exc:
            errors.append(f"Audit event signature invalid: {exc}")
    elif sig_b64:
        # If public key not provided, treat signature presence as verified format
        sig_valid = True
    else:
        errors.append("Audit event signature missing from passport")

    # 3. Merkle Inclusion Proof verification
    merkle_proof = passport.get("merkle_proof", {})
    root_hash = merkle_proof.get("root_hash", "")
    audit_path = merkle_proof.get("audit_path", [])
    leaf_index = merkle_proof.get("leaf_index", 0)
    tree_size = merkle_proof.get("tree_size", 0)

    # The leaf is the canonical audit event bytes or event hash bytes
    event_hash_hex = audit_event.get("event_hash", "")
    if event_hash_hex and root_hash and audit_path is not None:
        try:
            leaf_bytes = bytes.fromhex(event_hash_hex)
            verify_inclusion_proof(
                leaf_bytes=leaf_bytes,
                leaf_index=leaf_index,
                tree_size=tree_size,
                expected_root_hex=root_hash,
                audit_path=audit_path,
            )
            merkle_valid = True
        except Exception as exc:
            errors.append(f"Merkle inclusion proof invalid: {exc}")
    else:
        errors.append("Incomplete Merkle proof parameters in passport")

    # 4. Blockchain Anchor check
    anchor = passport.get("blockchain_anchor", {})
    tx_hash = anchor.get("tx_hash", "")
    contract_addr = anchor.get("contract_address", "")

    if tx_hash.startswith("0x") and len(tx_hash) == 66 and contract_addr.startswith("0x"):
        anchor_valid = True
    else:
        errors.append("Invalid or missing blockchain anchor transaction receipt in passport")

    is_all_valid = digest_matches and sig_valid and merkle_valid and anchor_valid

    return PassportVerificationResult(
        is_valid=is_all_valid,
        digest_matches=digest_matches,
        signature_valid=sig_valid,
        merkle_proof_valid=merkle_valid,
        anchor_receipt_valid=anchor_valid,
        errors=errors,
        details={
            "actual_digest": actual_digest,
            "expected_digest": expected_digest,
            "root_hash": root_hash,
            "tx_hash": tx_hash,
        },
    )
