"""EvidenceShield AI - Application Configuration."""

import os
from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    env: str = Field(default="development", alias="EVIDENCESHIELD_ENV")
    secret_key: str = Field(default="dev-secret-key-at-least-32-bytes-long!", alias="EVIDENCESHIELD_SECRET_KEY")
    api_prefix: str = Field(default="/api/v1", alias="EVIDENCESHIELD_API_PREFIX")
    base_url: str = Field(default="https://localhost:8443", alias="EVIDENCESHIELD_BASE_URL")

    # Session & MFA
    session_cookie_name: str = Field(default="evidenceshield_session", alias="SESSION_COOKIE_NAME")
    session_cookie_secure: bool = Field(default=False, alias="SESSION_COOKIE_SECURE")
    session_cookie_httponly: bool = Field(default=True, alias="SESSION_COOKIE_HTTPONLY")
    session_max_age_seconds: int = Field(default=28800, alias="SESSION_MAX_AGE_SECONDS")
    mfa_freshness_max_seconds: int = Field(default=600, alias="MFA_FRESHNESS_MAX_SECONDS")

    # Database
    database_url: str = Field(
        default="sqlite+aiosqlite:///./evidenceshield.db",
        alias="DATABASE_URL",
    )
    database_sync_url: str = Field(
        default="sqlite:///./evidenceshield.db",
        alias="DATABASE_SYNC_URL",
    )

    # Storage (SeaweedFS S3 or Local File System Mock)
    s3_endpoint_url: str = Field(default="http://localhost:8333", alias="S3_ENDPOINT_URL")
    s3_access_key: str = Field(default="seaweed_admin", alias="S3_ACCESS_KEY")
    s3_secret_key: str = Field(default="seaweed_secret", alias="S3_SECRET_KEY")
    s3_bucket_name: str = Field(default="evidence-ciphertext", alias="S3_BUCKET_NAME")
    s3_region: str = Field(default="us-east-1", alias="S3_REGION")
    local_storage_dir: str = Field(default="./storage_data", alias="LOCAL_STORAGE_DIR")

    # Vault
    vault_addr: str = Field(default="http://localhost:8200", alias="VAULT_ADDR")
    vault_token: str = Field(default="evidenceshield_vault_token_dev", alias="VAULT_TOKEN")
    vault_transit_key_name: str = Field(default="evidenceshield-dek", alias="VAULT_TRANSIT_KEY_NAME")

    # OPA
    opa_url: str = Field(default="http://localhost:8181/v1/data/evidenceshield/authz", alias="OPA_URL")

    # Keycloak
    keycloak_url: str = Field(default="http://localhost:8080", alias="KEYCLOAK_URL")
    keycloak_realm: str = Field(default="evidenceshield", alias="KEYCLOAK_REALM")
    keycloak_client_id: str = Field(default="evidenceshield-backend", alias="KEYCLOAK_CLIENT_ID")
    keycloak_client_secret: str = Field(default="keycloak-client-secret-dev", alias="KEYCLOAK_CLIENT_SECRET")

    # Blockchain (Anvil)
    anvil_rpc_url: str = Field(default="http://localhost:8545", alias="ANVIL_RPC_URL")
    anchor_contract_address: str = Field(
        default="0x5FbDB2315678afecb367f032d93F642f64180aa3", alias="ANCHOR_CONTRACT_ADDRESS"
    )
    anchor_publisher_private_key: str = Field(
        default="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        alias="ANCHOR_PUBLISHER_PRIVATE_KEY",
    )
    chain_id: int = Field(default=31337, alias="CHAIN_ID")

    # AI & Workers
    ollama_base_url: str = Field(default="http://localhost:11434", alias="OLLAMA_BASE_URL")
    ollama_model: str = Field(default="qwen3:4b", alias="OLLAMA_MODEL")

    class Config:
        env_file = ".env"
        extra = "allow"


settings = Settings()
