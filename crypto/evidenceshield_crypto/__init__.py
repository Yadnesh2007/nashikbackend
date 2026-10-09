"""EvidenceShield Cryptography Engine.

Package implementing cryptographic primitives, RFC 8785 canonicalization,
RFC 9162 domain-separated Merkle trees, AES-256-GCM authenticated encryption,
Ed25519 signing, Evidence Passport generation, and independent verification.
"""

from .crypto import (
    encrypt_version_bytes,
    decrypt_version_bytes,
    compute_sha256_hex,
    CiphertextAuthError,
    DigestMismatchError,
    CryptoError,
)
from .canonical import canonicalize_json
from .signing import (
    generate_signing_keypair,
    sign_canonical_payload,
    verify_canonical_payload,
    SignatureInvalidError,
)
from .merkle import (
    MerkleTree,
    verify_inclusion_proof,
    verify_consistency_proof,
    MerkleProofError,
)
from .passport import (
    generate_evidence_passport,
    verify_evidence_passport,
    PassportVerificationResult,
)
from .detector import (
    verify_evidence_integrity,
    IntegrityCheckResult,
    FailureStage,
)

__all__ = [
    "encrypt_version_bytes",
    "decrypt_version_bytes",
    "compute_sha256_hex",
    "CiphertextAuthError",
    "DigestMismatchError",
    "CryptoError",
    "canonicalize_json",
    "generate_signing_keypair",
    "sign_canonical_payload",
    "verify_canonical_payload",
    "SignatureInvalidError",
    "MerkleTree",
    "verify_inclusion_proof",
    "verify_consistency_proof",
    "MerkleProofError",
    "generate_evidence_passport",
    "verify_evidence_passport",
    "PassportVerificationResult",
    "verify_evidence_integrity",
    "IntegrityCheckResult",
    "FailureStage",
]
