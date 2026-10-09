"""Standalone Evidence Passport Verifier CLI.

Runs completely independently without database or network access.
"""

import argparse
import json
import sys

from .passport import verify_evidence_passport


def main():
    parser = argparse.ArgumentParser(description="EvidenceShield Standalone Passport Verifier")
    parser.add_argument("file", help="Path to evidence file to verify")
    parser.add_argument("passport", help="Path to signed Evidence Passport JSON file")
    parser.add_argument("--public-key", help="Optional hex or raw path to trusted Ed25519 public key", default=None)

    args = parser.parse_args()

    try:
        with open(args.file, "rb") as f:
            file_bytes = f.read()

        with open(args.passport, "r") as f:
            passport_data = json.load(f)

        pub_key_bytes = None
        if args.public_key:
            pub_key_bytes = bytes.fromhex(args.public_key)

        result = verify_evidence_passport(file_bytes, passport_data, trusted_public_key=pub_key_bytes)

        print("\n=== EvidenceShield Independent Verification Result ===")
        print(f"Overall Valid: {result.is_valid}")
        print(f"  - Plaintext SHA-256 Match: {result.digest_matches}")
        print(f"  - Ed25519 Audit Signature: {result.signature_valid}")
        print(f"  - Merkle Inclusion Proof:  {result.merkle_proof_valid}")
        print(f"  - Blockchain Anchor Valid: {result.anchor_receipt_valid}")

        if result.errors:
            print("\nVerification Errors:")
            for err in result.errors:
                print(f"  [X] {err}")
            sys.exit(1)
        else:
            print("\n[OK] Evidence file cryptographically matches its immutable Passport.")
            sys.exit(0)

    except Exception as exc:
        print(f"Verification execution error: {exc}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
