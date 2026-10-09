"""Ed25519 signing and verification over RFC 8785 canonical JSON bytes."""

import base64
import hashlib
from typing import Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from .canonical import canonicalize_json


class SignatureInvalidError(Exception):
    """Raised when an Ed25519 signature verification fails."""
    pass


def generate_signing_keypair() -> Tuple[bytes, bytes]:
    """Generates an Ed25519 keypair.

    Returns:
        (private_key_bytes, public_key_bytes) where both are raw 32-byte seeds/keys.
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_bytes, pub_bytes


def sign_canonical_payload(data: dict, private_key_raw: bytes) -> Tuple[str, str]:
    """Canonicalizes data per RFC 8785, hashes with SHA-256, and signs with Ed25519.

    Returns:
        (signature_base64, payload_digest_hex)
    """
    canonical_bytes = canonicalize_json(data)
    payload_digest_hex = hashlib.sha256(canonical_bytes).hexdigest()

    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_raw)
    signature = private_key.sign(canonical_bytes)
    signature_b64 = base64.b64encode(signature).decode("ascii")

    return signature_b64, payload_digest_hex


def verify_canonical_payload(data: dict, signature_b64: str, public_key_raw: bytes) -> bool:
    """Verifies Ed25519 signature over canonical JSON bytes."""
    try:
        canonical_bytes = canonicalize_json(data)
        signature = base64.b64decode(signature_b64.encode("ascii"))
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_raw)
        public_key.verify(signature, canonical_bytes)
        return True
    except (InvalidSignature, ValueError, Exception) as exc:
        raise SignatureInvalidError(f"Ed25519 signature validation failed: {exc}") from exc
