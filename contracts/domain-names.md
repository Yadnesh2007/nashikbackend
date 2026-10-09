# EvidenceShield AI - Domain Names & Identification Standard

**Revision:** 1.0.0-s2  
**Baseline:** S2 Implementation Specification  
**Status:** Frozen Common Contract  

This document standardizes the domain names, wire spellings, identifiers, enums, and transport formats across the Frontend, Backend, and Cryptography Engine.

---

## 1. Identifiers & Wire Spellings

All identifiers in JSON requests, responses, database columns, and audit payloads MUST use lowercase `snake_case`.

| Wire Field | Description | Type / Format | Example |
|---|---|---|---|
| `case_id` | Unique identifier for a judicial/investigative case | UUIDv4 (hyphenated, lowercase) | `"c7b2a9e0-82a1-4b13-912f-6825a07e1123"` |
| `case_number` | Human-readable case or FIR reference | String (uppercase alphanumeric with dashes) | `"FIR-2026-MUM-0891"` |
| `document_id` | Unique identifier for an evidentiary document entity | UUIDv4 | `"d14a58b2-7634-4f80-9ea3-90d2381e4b88"` |
| `version_id` | Unique identifier for an immutable document version | UUIDv4 | `"v981f23c-15a4-41b2-bf9e-10842e617d91"` |
| `transfer_id` | Unique identifier for a chain of custody transfer | UUIDv4 | `"t55a4099-23c1-42ab-8e01-5231c4aa99bb"` |
| `alert_id` | Unique identifier for an integrity alert | UUIDv4 | `"a8813204-c288-466d-85fa-7182283e0011"` |
| `job_id` | Unique identifier for an asynchronous worker job | UUIDv4 | `"j12089ef-3312-45e3-9978-2b890cc11244"` |
| `checkpoint_id` | Identifier for an audit log Merkle checkpoint | String | `"chk_00000001"` |
| `sequence_id` | Monotonic 64-bit sequence in audit ledger | Integer (uint64) | `1042` |
| `digest` | Plaintext SHA-256 digest of original file bytes | 64-character lowercase hex string | `"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"` |
| `input_digest` | Input plaintext SHA-256 for derivative processing | 64-character lowercase hex string | `"4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"` |
| `output_digest` | Output plaintext SHA-256 for derivative processing | 64-character lowercase hex string | `"a291bf03248817290d291e1c3a6e9a7e0c4b22194b150931d8f8a61901de49aa"` |
| `object_key` | Ciphertext reference in SeaweedFS S3 storage | String (`case_id/document_id/version_id.bin`) | `"c7b2a9e0/d14a58b2/v981f23c.bin"` |
| `nonce` | AES-256-GCM 96-bit initialization vector | 24-character Base64 string | `"q90dK821lmNP90a+3x79sw=="` |
| `tag` | AES-256-GCM 128-bit authentication tag | 24-character Base64 string (or 32-char hex) | `"Yk2/m987VbN002Lm1k98AQ=="` |
| `wrapped_key` | Vault Transit ciphertext of 256-bit DEK | String prefixed with `vault:v1:` | `"vault:v1:7Ym3...90="` |
| `key_id` | Identifier of the Vault key or platform signing key | String | `"transit/keys/evidenceshield-dek"` |
| `tx_hash` | Blockchain transaction hash on Anvil local chain | 66-character hex string starting with `0x` | `"0x3b890a...21"` |

---

## 2. Standard Enums

### 2.1 Role Enums (`role`)

Authoritative server roles configured in Keycloak and evaluated by OPA:

- `POLICE`: Investigating Officer / First Responder. Can upload original evidence, initiate custody handoffs, view assigned cases.
- `FORENSIC_LAB`: Digital / Physical Forensic Examiner. Can accept evidence transfers, upload forensic derivative reports, conduct technical verifications.
- `PROSECUTOR`: Public Prosecutor / Judicial Officer. Can view case files, cited AI analysis, inconsistency reviews, readiness preflight, and generate verified court export packages.
- `SYSTEM_ADMIN`: Platform Administrator. Manages user provisioning, system health, service metrics. **STRICT ZERO-TRUST RULE: Cannot decrypt evidence ciphertext or self-grant case document access.**
- `AUDITOR`: Independent Integrity Auditor. Read-only access to audit events, Merkle proofs, chain anchor receipts, and verification logs.

### 2.2 Document States (`state`)

Preserved exact lifecycle states:

- `INGESTING`: Upload session initialized, stream encryption in progress, or pending metadata validation.
- `READY_PENDING_ANCHOR`: File encrypted and stored in SeaweedFS, baseline signature committed to audit ledger. Awaiting Merkle checkpoint anchor on-chain. Uploader inspection permitted under signed baseline.
- `VERIFIED_ANCHORED`: Confirmed anchored on local blockchain with valid Merkle inclusion proof and transaction receipt. Eligible for transfer, sealing, and proof-backed export.
- `QUARANTINED`: Integrity or cryptographic verification failed (e.g., GCM tag mismatch, hash mismatch, altered proof). Ordinary download, AI analysis, and transfers are strictly BLOCKED.
- `FAILED`: Unrecoverable upload, parser error, or storage failure during initial ingestion.

### 2.3 Classifications (`classification`)

- `INTERNAL`: Standard case material visible to any officer assigned to the case.
- `SENSITIVE`: Evidentiary material requiring direct case assignment or explicit document-level grant.
- `RESTRICTED`: High-sensitivity material requiring lead investigator role and fresh MFA within 10 minutes.

### 2.4 Transfer States (`transfer_state`)

- `PENDING`: Initiated by sender; awaiting action by designated recipient.
- `ACCEPTED`: Acknowledged and accepted by designated recipient with signed receipt.
- `REJECTED`: Declined by designated recipient with stated rationale.
- `CANCELLED`: Withdrawn by sender prior to recipient action.

### 2.5 Alert Statuses (`alert_status`)

- `OPEN`: Newly detected anomaly awaiting review.
- `INVESTIGATING`: Assigned reviewer is examining the flagged version.
- `CONFIRMED_TAMPERED`: Reviewer confirmed malicious or accidental data modification.
- `DISMISSED_FALSE_POSITIVE`: Reviewer dismissed alert with audited rationale. *(Note: Dismissing an alert does NOT automatically un-quarantine evidence unless cryptographic re-verification passes).*

### 2.6 Job Statuses (`job_status`)

- `PENDING`: Queued in transactional outbox / job table.
- `RUNNING`: Acquired by worker with active heartbeat lease.
- `COMPLETED`: Successfully finished with recorded results.
- `FAILED`: Exhausted retry budget with recorded error stack.

---

## 3. Date & Timestamp Representation

- All server timestamps MUST be represented in **UTC** adhering to **ISO-8601** format with trailing `Z`:  
  `YYYY-MM-DDTHH:MM:SSZ` (e.g., `2026-10-09T14:32:00Z`).
- Sub-second precision (if present) MUST use microseconds: `YYYY-MM-DDTHH:MM:SS.ffffffZ`.
- `declared_capture_time`: Original device timestamp reported by body camera or scanner, recorded as ISO-8601 string.
- `declared_timezone`: Declared IANA timezone name (e.g., `"Asia/Kolkata"`, `"UTC"`).
- `committed_at`: Authoritative database commit timestamp allocated monotonically by PostgreSQL.

---

## 4. API Response Envelope

Standard pagination envelope:
```json
{
  "items": [],
  "total": 42,
  "limit": 20,
  "offset": 0
}
```

Standard error envelope (RFC 7807):
```json
{
  "type": "https://evidenceshield.local/errors/CIPHERTEXT_AUTH_FAILED",
  "title": "Ciphertext Authentication Failed",
  "status": 422,
  "detail": "AES-256-GCM authentication tag mismatch during decryption.",
  "instance": "/api/v1/versions/v981f23c-15a4-41b2-bf9e-10842e617d91/content",
  "code": "CIPHERTEXT_AUTH_FAILED",
  "timestamp": "2026-10-09T14:32:00Z"
}
```
