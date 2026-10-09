# EvidenceShield AI - Cryptographic Interface Specification

**Revision:** 1.0.0-s2  
**Baseline:** S2 Implementation Specification  
**Status:** Frozen Common Contract  
**Owning Component:** Machine C (`evidenceshield_crypto` package)  
**Consuming Component:** Machine B (`backend/`)  

---

## 1. Overview & Trust Boundaries

The Cryptography Engine (`evidenceshield_crypto`) is responsible for all cryptographic primitives, byte canonicalization, authenticated encryption, Ed25519 digital signatures, RFC 9162 Merkle proof generation/verification, Anvil smart contract interaction, Evidence Passport construction, and standalone offline verification.

The Backend (`backend/`) imports `evidenceshield_crypto` as a library and invokes its deterministic methods. The Backend MUST NOT invent competing cryptographic formats or serialization rules.

---

## 2. Authenticated Encryption (AES-256-GCM)

Complies with NIST SP 800-38D.

### 2.1 Encryption Parameters
- **Algorithm:** `AES-256-GCM`
- **Data Encryption Key (DEK):** Freshly generated cryptographically secure 256-bit (32-byte) key per document version.
- **Initialization Vector (Nonce):** Freshly generated 96-bit (12-byte) random nonce per version. **NEVER REUSE A NONCE.**
- **Authentication Tag:** 128-bit (16-byte) tag output from AES-GCM.
- **Key Wrapping:** The DEK is passed to HashiCorp Vault Transit engine (`transit/encrypt/evidenceshield-dek`) to generate a `wrapped_key` ciphertext string (or encrypted using platform master key in offline test vectors).

### 2.2 Authenticated Additional Data (AAD)
To prevent cross-entity tampering or transplant attacks, the AES-GCM cipher binds the resource identity as AAD.

Canonical AAD Schema (RFC 8785 Canonical JSON):
```json
{
  "case_id": "c7b2a9e0-82a1-4b13-912f-6825a07e1123",
  "document_id": "d14a58b2-7634-4f80-9ea3-90d2381e4b88",
  "format": "application/pdf",
  "version_id": "v981f23c-15a4-41b2-bf9e-10842e617d91"
}
```
*Note: Keys MUST be sorted lexicographically with no whitespace outside strings before converting to UTF-8 bytes.*

### 2.3 Python Signature
```python
def encrypt_version_bytes(
    plaintext: bytes,
    case_id: str,
    document_id: str,
    version_id: str,
    format_mimetype: str,
    dek: bytes = None,
) -> tuple[bytes, str, str, str, str]:
    """
    Returns:
      (ciphertext_bytes, nonce_b64, tag_b64, digest_sha256_hex, raw_dek_hex)
    """

def decrypt_version_bytes(
    ciphertext: bytes,
    dek: bytes,
    nonce_b64: str,
    tag_b64: str,
    case_id: str,
    document_id: str,
    version_id: str,
    format_mimetype: str,
    expected_digest: str = None,
) -> bytes:
    """
    Authenticates AAD and decrypts ciphertext.
    Re-computes SHA-256 of plaintext and verifies against expected_digest.
    Raises:
      CiphertextAuthError on GCM tag mismatch
      DigestMismatchError on SHA-256 discrepancy
    """
```

---

## 3. Canonical JSON & Ed25519 Signatures

### 3.1 Canonicalization (RFC 8785)
All structured metadata signed by the platform (Audit Events, Checkpoints, Passports) MUST be canonicalized according to RFC 8785 (JCS):
- Whitespace removed.
- Object keys sorted lexicographically by UTF-16 code units.
- Numbers formatted canonically.

### 3.2 Digital Signatures
- **Algorithm:** `Ed25519` (PureEdDSA, RFC 8032).
- **Public Key:** 32-byte Ed25519 public key, serialized as 64-char hex or Base64.
- **Signature:** 64-byte Ed25519 signature, serialized as Base64 or hex.

### 3.3 Python Signature
```python
def canonicalize_json(data: dict) -> bytes:
    """Produces RFC 8785 deterministic UTF-8 bytes."""

def sign_canonical_payload(data: dict, private_key_pem_or_bytes: bytes) -> tuple[str, str]:
    """
    Returns:
      (signature_b64, payload_digest_hex)
    """

def verify_canonical_payload(data: dict, signature_b64: str, public_key_bytes: bytes) -> bool:
    """Verifies Ed25519 signature over canonical JSON bytes."""
```

---

## 4. RFC 9162 Merkle Tree & Audit Proofs

Implements Certificate Transparency (RFC 9162) domain-separated hashing:
- **Leaf Hash:** `SHA-256(0x00 || leaf_data_bytes)`
- **Interior Node Hash:** `SHA-256(0x01 || left_child_hash || right_child_hash)`

### 4.1 Proof Structures
- **Inclusion Proof (Audit Path):** Array of sibling hashes verifying that an event at `leaf_index` is included in a tree of size `N` with root `R`.
- **Consistency Proof:** Array of intermediate hashes proving that a tree of size `M` is a prefix of a tree of size `N` (`M <= N`).

### 4.2 Python Signature
```python
class MerkleTree:
    def __init__(self, leaves: list[bytes]):
        """Constructs tree with RFC 9162 domain separation."""
        
    def get_root_hash(self) -> str:
        """Returns 64-character hex root hash."""
        
    def get_inclusion_proof(self, leaf_index: int) -> list[dict]:
        """
        Returns list of proof steps: [{"direction": "left"|"right", "hash": "hex"}]
        """
        
    def get_consistency_proof(self, prev_tree_size: int) -> list[str]:
        """Returns consistency proof hashes."""
```

---

## 5. Local Blockchain (Anvil) Anchor Contract

### 5.1 Solidity Smart Contract (`EvidenceAnchor.sol`)
```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

contract EvidenceAnchor {
    address public owner;
    
    struct Checkpoint {
        uint64 treeSize;
        bytes32 merkleRoot;
        bytes32 prevRoot;
        uint256 timestamp;
        string publisherIdentity;
    }
    
    mapping(string => Checkpoint[]) public ledgerCheckpoints;
    event CheckpointAnchored(string indexed ledgerId, uint64 treeSize, bytes32 merkleRoot, uint256 timestamp);

    constructor() {
        owner = msg.sender;
    }

    function anchorCheckpoint(
        string calldata ledgerId,
        uint64 treeSize,
        bytes32 merkleRoot,
        bytes32 prevRoot,
        string calldata publisherIdentity
    ) external returns (bool) {
        require(msg.sender == owner, "Unauthorized publisher");
        uint256 len = ledgerCheckpoints[ledgerId].length;
        if (len > 0) {
            require(treeSize > ledgerCheckpoints[ledgerId][len - 1].treeSize, "Stale tree size");
            require(prevRoot == ledgerCheckpoints[ledgerId][len - 1].merkleRoot, "Invalid prev root");
        }
        
        ledgerCheckpoints[ledgerId].push(Checkpoint({
            treeSize: treeSize,
            merkleRoot: merkleRoot,
            prevRoot: prevRoot,
            timestamp: block.timestamp,
            publisherIdentity: publisherIdentity
        }));
        
        emit CheckpointAnchored(ledgerId, treeSize, merkleRoot, block.timestamp);
        return true;
    }
}
```

---

## 6. Evidence Passport Specification

The Evidence Passport is a self-contained, tamper-evident cryptographic receipt exported as JSON and bundled with evidence files.

```json
{
  "passport_version": "1.0",
  "document": {
    "case_id": "c7b2a9e0-82a1-4b13-912f-6825a07e1123",
    "document_id": "d14a58b2-7634-4f80-9ea3-90d2381e4b88",
    "version_id": "v981f23c-15a4-41b2-bf9e-10842e617d91",
    "file_name": "witness_statement_01.pdf",
    "mime_type": "application/pdf",
    "digest_sha256": "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    "size_bytes": 1048576,
    "declared_capture_time": "2026-10-09T09:15:00Z",
    "committed_at": "2026-10-09T09:17:22Z"
  },
  "audit_event": {
    "sequence_id": 1042,
    "event_type": "DOCUMENT_INGESTED",
    "event_hash": "b8a901...33",
    "signature": "MEQCIF98...==",
    "signing_key_id": "key_ed25519_2026_01"
  },
  "merkle_proof": {
    "checkpoint_id": "chk_00000001",
    "tree_size": 25,
    "leaf_index": 12,
    "root_hash": "c920ba...88",
    "audit_path": [
      {"direction": "left", "hash": "a1b2..."},
      {"direction": "right", "hash": "c3d4..."}
    ]
  },
  "blockchain_anchor": {
    "chain_id": 31337,
    "contract_address": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
    "tx_hash": "0x89ab...ef",
    "block_number": 42,
    "confirmed_at": "2026-10-09T09:18:00Z"
  }
}
```

---

## 7. Cryptographic Error Taxonomy

| Error Code | HTTP Status | Description |
|---|---|---|
| `CIPHERTEXT_AUTH_FAILED` | 422 | AES-GCM tag mismatch. Indicates bit-flip or corrupted ciphertext. |
| `DIGEST_MISMATCH` | 422 | Decrypted plaintext SHA-256 does not match committed digest. |
| `SIGNATURE_INVALID` | 400 | Ed25519 signature over canonical event/checkpoint failed. |
| `MERKLE_PROOF_INVALID` | 400 | RFC 9162 inclusion/consistency path does not match root. |
| `OBJECT_NOT_FOUND` | 404 | Ciphertext object key missing in SeaweedFS. |
| `CHAIN_RECEIPT_MISSING` | 400 | Anchor transaction failed or receipt not found on chain. |
| `QUARANTINE_ACTIVE` | 403 | Resource is quarantined; plain retrieval is forbidden. |
