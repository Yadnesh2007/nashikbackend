"""AES-256-GCM authenticated encryption and decryption bound to canonical AAD."""

import base64
import hashlib
import os
from typing import Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .canonical import canonicalize_json


class CryptoError(Exception):
    """Base exception for cryptographic errors."""
    pass


class CiphertextAuthError(CryptoError):
    """Raised when AES-GCM ciphertext fails authentication (tag mismatch)."""
    pass


class DigestMismatchError(CryptoError):
    """Raised when decrypted plaintext SHA-256 does not match expected digest."""
    pass


def compute_sha256_hex(data: bytes) -> str:
    """Computes lowercase 64-char SHA-256 digest of bytes."""
    return hashlib.sha256(data).hexdigest()


def build_canonical_aad(
    case_id: str,
    document_id: str,
    version_id: str,
    format_mimetype: str,
) -> bytes:
    """Constructs RFC 8785 canonical bytes for Authenticated Additional Data."""
    aad_dict = {
        "case_id": str(case_id),
        "document_id": str(document_id),
        "format": str(format_mimetype),
        "version_id": str(version_id),
    }
    return canonicalize_json(aad_dict)


def encrypt_version_bytes(
    plaintext: bytes,
    case_id: str,
    document_id: str,
    version_id: str,
    format_mimetype: str,
    dek: Optional[bytes] = None,
) -> Tuple[bytes, str, str, str, str]:
    """Encrypts raw version bytes using AES-256-GCM with AAD binding.

    Args:
        plaintext: Raw file bytes
        case_id: Target case UUID string
        document_id: Target document UUID string
        version_id: Version UUID string
        format_mimetype: MIME type (e.g. application/pdf)
        dek: Optional 32-byte key. If None, generated with os.urandom(32).

    Returns:
        (ciphertext_bytes, nonce_b64, tag_b64, digest_sha256_hex, raw_dek_hex)
    """
    if dek is None:
        dek = os.urandom(32)
    elif len(dek) != 32:
        raise ValueError("DEK must be exactly 32 bytes (256 bits).")

    nonce = os.urandom(12)  # 96-bit nonce
    aad_bytes = build_canonical_aad(case_id, document_id, version_id, format_mimetype)

    aesgcm = AESGCM(dek)
    # cryptography AESGCM.encrypt appends 16-byte tag to the ciphertext
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, aad_bytes)
    ciphertext = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]

    digest_hex = compute_sha256_hex(plaintext)
    nonce_b64 = base64.b64encode(nonce).decode("ascii")
    tag_b64 = base64.b64encode(tag).decode("ascii")
    dek_hex = dek.hex()

    return ciphertext, nonce_b64, tag_b64, digest_hex, dek_hex


def decrypt_version_bytes(
    ciphertext: bytes,
    dek: bytes,
    nonce_b64: str,
    tag_b64: str,
    case_id: str,
    document_id: str,
    version_id: str,
    format_mimetype: str,
    expected_digest: Optional[str] = None,
) -> bytes:
    """Authenticates and decrypts ciphertext using AES-256-GCM.

    Re-computes SHA-256 and verifies against expected_digest.

    Raises:
        CiphertextAuthError: If authentication tag check fails (e.g. bit-flip)
        DigestMismatchError: If decrypted bytes do not match expected_digest
    """
    try:
        nonce = base64.b64decode(nonce_b64.encode("ascii"))
        tag = base64.b64decode(tag_b64.encode("ascii"))
    except Exception as exc:
        raise CiphertextAuthError(f"Invalid Base64 nonce or tag: {exc}") from exc

    if len(nonce) != 12:
        raise CiphertextAuthError(f"Invalid nonce length: expected 12 bytes, got {len(nonce)}")
    if len(tag) != 16:
        raise CiphertextAuthError(f"Invalid tag length: expected 16 bytes, got {len(tag)}")

    aad_bytes = build_canonical_aad(case_id, document_id, version_id, format_mimetype)
    ct_with_tag = ciphertext + tag

    aesgcm = AESGCM(dek)
    try:
        plaintext = aesgcm.decrypt(nonce, ct_with_tag, aad_bytes)
    except InvalidTag as exc:
        raise CiphertextAuthError("AES-256-GCM authentication failed: tag mismatch (ciphertext or AAD modified).") from exc
    except Exception as exc:
        raise CiphertextAuthError(f"Decryption error: {exc}") from exc

    if expected_digest:
        actual_digest = compute_sha256_hex(plaintext)
        if actual_digest.lower() != expected_digest.lower():
            raise DigestMismatchError(
                f"Plaintext SHA-256 digest mismatch! Expected {expected_digest}, computed {actual_digest}"
            )

    return plaintext
