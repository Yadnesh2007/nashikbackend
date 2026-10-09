# EvidenceShield AI - Runtime Environment & Configuration Specification

**Revision:** 1.0.0-s2  
**Baseline:** S2 Implementation Specification  
**Status:** Frozen Common Contract  

This document specifies the service network topology, environment variable keys, container pins, secrets, and startup orchestration.

---

## 1. Network Topology & Ports

In accordance with Section 11 of the architecture baseline:
- Only the **HTTPS Gateway** (NGINX on port `8443` or `443`) and local dev API port (`8000`) are accessible to clients.
- Database, Object Storage, Keycloak, Vault, OPA, Anvil, and Ollama remain internal on the Docker Compose network (`evidenceshield_net`).

| Service Name | Internal DNS Name | Internal Port | External Port | Pinned Image / Engine | Purpose |
|---|---|---|---|---|---|
| `gateway` | `gateway` | `443` | `8443` | `nginx:1.25-alpine` | Reverse proxy, TLS termination, CSRF & security headers |
| `backend` | `backend` | `8000` | `8000` | Python 3.11 / FastAPI | Authoritative API & workflow orchestration |
| `postgres` | `postgres` | `5432` | *(internal)* | `postgres:16-alpine` | Relational persistence, transactional outbox, audit ledger |
| `seaweedfs` | `seaweedfs` | `8333` | *(internal)* | `chrislusf/seaweedfs:latest` | S3-compatible ciphertext blob store |
| `keycloak` | `keycloak` | `8080` | *(internal)* | `quay.io/keycloak/keycloak:24.0` | OIDC, TOTP MFA, user directory |
| `vault` | `vault` | `8200` | *(internal)* | `hashicorp/vault:1.16` | Transit secret engine (key wrapping, key rotation) |
| `opa` | `opa` | `8181` | *(internal)* | `openpolicyagent/opa:0.63.0` | ABAC policy evaluation engine |
| `anvil` | `anvil` | `8545` | *(internal)* | `ghcr.io/foundry-rs/foundry:latest` | Local EVM blockchain node for anchor contract |
| `ollama` | `ollama` | `11434` | *(internal)* | `ollama/ollama:latest` | Local LLM host pinned to `qwen3:4b` |
| `tesseract-worker`| `tesseract-worker`| N/A | *(internal)* | Python 3.11 + Tesseract 5.3 | Isolated OCR background worker |

---

## 2. Configuration Keys & Environment Variables

All configuration keys MUST follow the exact casing and prefixes specified below:

```bash
# Application General
EVIDENCESHIELD_ENV=production
EVIDENCESHIELD_SECRET_KEY=change-in-production-super-secret-key-32b
EVIDENCESHIELD_BASE_URL=https://localhost:8443
EVIDENCESHIELD_API_PREFIX=/api/v1
SESSION_COOKIE_NAME=evidenceshield_session
SESSION_COOKIE_SECURE=true
SESSION_COOKIE_HTTPONLY=true
SESSION_MAX_AGE_SECONDS=28800
MFA_FRESHNESS_MAX_SECONDS=600

# PostgreSQL
DATABASE_URL=postgresql+asyncpg://evidenceshield:evidenceshield_pass@postgres:5432/evidenceshield_db
DATABASE_SYNC_URL=postgresql://evidenceshield:evidenceshield_pass@postgres:5432/evidenceshield_db

# SeaweedFS / S3 Ciphertext Storage
S3_ENDPOINT_URL=http://seaweedfs:8333
S3_ACCESS_KEY=seaweed_admin
S3_SECRET_KEY=seaweed_secret
S3_BUCKET_NAME=evidence-ciphertext
S3_REGION=us-east-1

# HashiCorp Vault
VAULT_ADDR=http://vault:8200
VAULT_TOKEN=evidenceshield_vault_token_dev
VAULT_TRANSIT_KEY_NAME=evidenceshield-dek
VAULT_SIGNING_KEY_NAME=evidenceshield-signing

# Open Policy Agent (OPA)
OPA_URL=http://opa:8181/v1/data/evidenceshield/authz

# Keycloak OIDC
KEYCLOAK_URL=http://keycloak:8080
KEYCLOAK_REALM=evidenceshield
KEYCLOAK_CLIENT_ID=evidenceshield-backend
KEYCLOAK_CLIENT_SECRET=keycloak-client-secret-dev

# Anvil / Blockchain Anchor
ANVIL_RPC_URL=http://anvil:8545
ANCHOR_CONTRACT_ADDRESS=0x5FbDB2315678afecb367f032d93F642f64180aa3
ANCHOR_PUBLISHER_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
CHAIN_ID=31337

# Ollama Local AI & Workers
OLLAMA_BASE_URL=http://ollama:11434
OLLAMA_MODEL=qwen3:4b
TESSERACT_LANG=eng
```

---

## 3. Seed Users & Identities for Five-Minute Flow

| Username | Role | Agency | MFA Configured | Purpose |
|---|---|---|---|---|
| `officer_sharma` | `POLICE` | `MUMBAI_CRIME_BRANCH` | Yes (TOTP) | Uploads FIR statement, initiates transfer |
| `examiner_patel` | `FORENSIC_LAB` | `STATE_FORENSIC_SCI_LAB` | Yes (TOTP) | Accepts transfer, uploads forensic analysis |
| `prosecutor_iyer` | `PROSECUTOR` | `MAHARASHTRA_PROSECUTION` | Yes (TOTP) | Reviews cited AI, readiness, exports evidence package |
| `auditor_verma` | `AUDITOR` | `INDEPENDENT_JUDICIAL_AUDIT`| Yes (TOTP) | Verifies audit sequence and Merkle consistency |
| `unauthorized_cop` | `POLICE` | `DELHI_SPECIAL_CELL` | Yes (TOTP) | Used in Demo step 2 to demonstrate cross-case 403 denial |
| `admin_user` | `SYSTEM_ADMIN` | `COURT_ADMINISTRATION` | Yes (TOTP) | System admin (strictly cannot decrypt evidence) |
