# EvidenceShield AI - Backend & Integration Runbook

**System:** Tamper-Evident Zero-Trust Judicial & Forensic Document Management System  
**Version:** 1.0.0-s2  
**Local Baseline:** S2 Implementation Specification  
**Component Ownership:** `backend/`, `contracts/`, `fixtures/`, `policies/`, `deploy/`, integration orchestration.  

---

## 1. Quickstart & Local Verification

### 1.1 Prerequisites
- Python 3.9+ (or 3.11 recommended)
- OpenSSL / Cryptography libraries
- Docker & Docker Compose (for containerized gateway & services)

### 1.2 Initialize Environment & Run Verification Suite
```bash
# 1. Activate virtual environment
source .venv/bin/activate

# 2. Run the complete automated test suite (including 5-minute acceptance flow)
pytest tests -v
```
**Expected Outcome:** All 13 test suites pass, demonstrating zero-trust denial, upload encryption, 1-bit corruption detection with automatic quarantine, custody transfer receipts, derivative lineage, cited review, and standalone Passport verification.

### 1.3 Initialize and Seed Database
```bash
python backend/seed.py
```
This idempotently initializes the schema, registers seed users (`officer_sharma`, `examiner_patel`, `prosecutor_iyer`, `auditor_verma`), seeds baseline cases (`FIR-2026-MUM-0891`), encrypts baseline documents, appends audit events, and anchors the initial Merkle checkpoint.

### 1.4 Standalone Offline Passport Verification
To verify evidence without any database connection:
```bash
evidenceshield-verify <path-to-file> <path-to-passport.json>
```
The verifier recomputes the plaintext SHA-256 digest, validates the RFC 9162 Merkle inclusion proof against the checkpoint root, and verifies the platform signature.

---

## 2. Docker Compose Deployment & Gateway

To run all private microservices and expose only the reverse proxy gateway:
```bash
cd deploy
docker compose up -d
```

### Network Topology:
- **Public Port:** `8443` (HTTPS) / `8000` (API Gateway)
- **Private Internal Network:** PostgreSQL (`5432`), SeaweedFS (`8333`), Vault (`8200`), OPA (`8181`), Anvil (`8545`), Ollama (`11434`).

---

## 3. Five-Minute Judging Demonstration Script

| Time | Action | What is Demonstrated | Expected System Behavior |
|---|---|---|---|
| **0:00 - 0:40** | Police Upload | Statement upload, SHA-256 baseline, AES-256-GCM encryption with bound AAD, Vault key wrapping | Status set to `READY_PENDING_ANCHOR`, then `VERIFIED_ANCHORED` once Merkle checkpoint is confirmed on Anvil. |
| **0:40 - 1:05** | Unauthorized Access Attempt | Delhi police officer attempts to access Mumbai case | Authoritative OPA ABAC denial (`403 Forbidden`). Audit event `UNAUTHORIZED_ACCESS_DENIED` logged. |
| **1:05 - 1:50** | Custody Transfer & Gap Rule | Police dispatches evidence to Forensic Lab | Before acceptance, preflight readiness flags `MISSING_ACKNOWLEDGMENT` custody gap. Designated recipient (`examiner_patel`) accepts with platform-signed receipt. |
| **1:50 - 2:35** | 1-Bit Corruption Harness | Flip 1 bit in stored ciphertext object | Multi-stage detector triggers `CIPHERTEXT_AUTH_FAILED` via AES-GCM tag mismatch. Version immediately locked in `QUARANTINED`. Ordinary download blocked. |
| **2:35 - 3:10** | Derivative Lineage | Forensic Lab registers extracted OCR text | Parent version remains immutable. Child version registered with operation metadata, tool version, and input/output digests. |
| **3:10 - 4:10** | Cited Review & Inconsistencies | Prosecutor opens AI summary & timeline | System presents exact source citations `[version_id, page, span, quote]`. 2-minute discrepancy between statement and telemetry flagged for human confirm/dismiss. |
| **4:10 - 5:00** | Readiness & Standalone Export | Prosecutor reviews readiness checklist & generates judicial export | Checks missing signatures, pending anchors, and unreviewed alerts. Independent verifier verifies exported Passport without database. |

---

## 4. Disaster Recovery & Runbooks

### 4.1 Chain Reset Recovery
If the local Anvil node restarts and resets its state:
1. `AnvilAnchorClient` detects that the contract address or block number has reset.
2. The durable outbox resumes publishing from the last trusted cumulative checkpoint.
3. Checkpoints retained off-chain in PostgreSQL and independent cold storage verify that historical roots remain untampered.

### 4.2 Backup & Restore
1. **PostgreSQL:** Dump schema and monotonic `audit_events` with sequence preservation.
2. **SeaweedFS:** Replicate ciphertext objects under `case_id/document_id/version_id.bin`.
3. **Vault Transit:** Backup encryption key keyring versions.

---

## 5. Non-Negotiable Claim Boundaries
- A cryptographic hash proves agreement with a trusted baseline; it does not prove real-world factual truth or author authenticity.
- 1-bit ciphertext corruption fails AES-GCM tag authentication before plaintext digest comparison.
- System signatures attest platform-recorded actions under authenticated sessions; they are not user-held private key PKI signatures.
- Local AI model suggestions require exact human verification; the system never produces automatic guilt or admissibility scores.
