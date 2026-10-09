# EvidenceShield AI - State Machine & Workflow Specification

**Revision:** 1.0.0-s2  
**Baseline:** S2 Implementation Specification  
**Status:** Frozen Common Contract  

This document defines the state transitions, pre-conditions, post-conditions, and behavioral invariants for documents, custody transfers, alerts, durable jobs, and evidence export packages.

---

## 1. Document Version Lifecycle State Machine

Each document version (`document_versions`) progresses through immutable lifecycle states:

```
  [ Upload Session ]
          │
          ▼
     INGESTING ──(Parser error / upload abort)──► FAILED
          │
          │ (AES-256-GCM encrypted, stored in SeaweedFS, baseline audit signed)
          ▼
 READY_PENDING_ANCHOR ──(Integrity/Digest Failure detected)──► QUARANTINED
          │                                                         ▲
          │ (Merkle tree checkpoint confirmed on Anvil chain)       │
          ▼                                                         │
  VERIFIED_ANCHORED ──(Ciphertext corruption / bad proof)───────────┘
```

### 1.1 State Definitions & Transition Matrix

| Initial State | Event / Trigger | Target State | Pre-conditions | Post-conditions & Side-effects |
|---|---|---|---|---|
| *(None)* | `POST /upload-sessions` | `INGESTING` | Requester has `case:write` permission on `case_id`. File size <= 25 MB, mime type in `[PDF, DOCX, TXT, JPG, PNG]`. | Upload session created in DB; session expires in 15 mins if unused. |
| `INGESTING` | `PUT /upload-sessions/{id}/content` | `READY_PENDING_ANCHOR` | Valid raw byte stream; page count <= 200 (if PDF); SHA-256 calculated on raw bytes. | Ciphertext written to SeaweedFS; wrapped DEK saved; monotonic audit event `DOCUMENT_INGESTED` committed. Outbox job created for Merkle checkpointing. |
| `INGESTING` | Parser crash, oversize, or stream failure | `FAILED` | Any failure during upload/encryption. | Session marked failed; partial objects cleaned up from storage; audit event `INGESTION_FAILED` recorded. |
| `READY_PENDING_ANCHOR` | Checkpoint worker confirms Anvil blockchain receipt | `VERIFIED_ANCHORED` | Tree includes event; tx receipt confirmed on Anvil; Merkle root matches on-chain state. | Version updated to `VERIFIED_ANCHORED`; audit event `VERSION_ANCHORED` committed with `tx_hash` and `block_number`. |
| `READY_PENDING_ANCHOR` or `VERIFIED_ANCHORED` | Bit-flip detected or tag/hash mismatch on retrieval or background sweep | `QUARANTINED` | Cryptographic check fails (`CIPHERTEXT_AUTH_FAILED`, `DIGEST_MISMATCH`, `SIGNATURE_INVALID`, or `MERKLE_PROOF_INVALID`). | Document version locked in `QUARANTINED`; `integrity_alerts` row generated; audit event `INTEGRITY_VIOLATION_QUARANTINED` committed. All standard download/AI paths blocked. |
| `QUARANTINED` | Reviewer dismissal without valid proof | *(Blocked)* | **INVARIANT: An alert dismissal cannot un-quarantine evidence unless cryptographic verification passes with 100% validity.** | None. State remains `QUARANTINED`. |

### 1.2 Access Rules by State
- `INGESTING`: Inaccessible except to active upload handler.
- `READY_PENDING_ANCHOR`: Readable **ONLY** by the original uploader under signed-baseline verification. Cannot be transferred, sealed, or exported.
- `VERIFIED_ANCHORED`: Full access to authorized case assignees/grantees. Eligible for custody transfer, derivative generation, AI analysis, and export.
- `QUARANTINED`: Blocked from standard GET `/versions/{id}/content`. Visible only in security/audit dashboards for assigned reviewers.
- `FAILED`: Inaccessible.

---

## 2. Custody Transfer State Machine

Custody transfers enforce the physical/digital chain of custody between investigating agencies (Police <-> Forensic Lab <-> Prosecutor).

```
   (Initiated by Sender)
             │
             ▼
          PENDING
         /       \
 (Recipient)    (Recipient)
     ▼              ▼
 ACCEPTED        REJECTED
```

### 2.1 Invariants & Business Rules
1. **Single Pending Transfer:** Exactly **ONE** pending transfer is permitted per `version_id` at any time.
2. **Anchor Prerequisite:** A version MUST be in `VERIFIED_ANCHORED` state before a transfer can be initiated.
3. **Designated Recipient Enforcement:** Only the principal identified in `recipient_id` (or authorized member of `recipient_agency`) can invoke `accept` or `reject`.
4. **Platform-Signed Receipts:**
   - On initiation: A platform-signed dispatch receipt is generated and linked.
   - On acceptance: A platform-signed acceptance receipt is generated with timestamp and cryptographic digest verification.
5. **Separation of Custody and Access:** Transferring custody records institutional responsibility. Access grants are separately managed by the policy engine.

---

## 3. Derivative Lineage State Machine

Derivatives represent forensic transformations (e.g., OCR extraction, redaction, forensic image enhancement).

- **Rule 1: Immutability of Parent:** The parent version is NEVER modified.
- **Rule 2: Child Version Registration:** The derivative is registered as a new immutable `document_version` record with its own `version_id`.
- **Rule 3: Lineage Registration:** A `derivative_lineage` record links `parent_version_id` to `child_version_id` containing:
  - `operation`: e.g., `OCR_EXTRACTION`, `IMAGE_DENOISING`, `REDACTION`.
  - `tool_name` & `tool_version`: Exact software binary and version (e.g. `tesseract 5.3.0`).
  - `operator_id`: The user performing the action.
  - `input_digest` & `output_digest`: SHA-256 digests of the input and output plaintext bytes.

---

## 4. Integrity Alerts & Review State Machine

```
   [ Violation Detected ]
             │
             ▼
           OPEN
             │ (Reviewer assigned)
             ▼
       INVESTIGATING
         /          \
   (Malicious)    (False positive verified)
        ▼                    ▼
 CONFIRMED_TAMPERED   DISMISSED_FALSE_POSITIVE
```

- When an integrity detector encounters a failure, it immediately creates an alert with status `OPEN`.
- Reviewer records findings in `disposition_notes`.
- Review decisions are committed to the append-only audit ledger.

---

## 5. Durable Jobs & Transactional Outbox

To guarantee reliable execution across PostgreSQL, SeaweedFS, and Anvil without false distributed-transaction assumptions:

1. **Transactional Outbox:**
   - Any state change requiring external side-effects (e.g., Anvil anchoring, OCR processing, email/webhook notification) inserts an outbox entry in the SAME database transaction as the entity mutation.
2. **Durable Worker Queue:**
   - Workers claim jobs using `SELECT ... FOR UPDATE SKIP LOCKED` with a lease expiration.
   - Successful execution marks job `COMPLETED`.
   - On failure, job enters exponential backoff up to 5 attempts before marking `FAILED`.
