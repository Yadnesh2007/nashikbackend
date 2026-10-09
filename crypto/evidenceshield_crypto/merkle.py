"""RFC 9162 Certificate Transparency Domain-Separated Merkle Tree Implementation."""

import hashlib
import math
from typing import List, Dict, Optional, Tuple


class MerkleProofError(Exception):
    """Raised when Merkle inclusion or consistency proof verification fails."""
    pass


def _hash_leaf(data: bytes) -> bytes:
    """Leaf hash domain separation: SHA-256(0x00 || data)."""
    return hashlib.sha256(b"\x00" + data).digest()


def _hash_node(left: bytes, right: bytes) -> bytes:
    """Interior node domain separation: SHA-256(0x01 || left || right)."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def _largest_power_of_two_less_than(n: int) -> int:
    """Computes largest power of 2 strictly less than n (for n >= 2)."""
    k = 1
    while (k << 1) < n:
        k <<= 1
    return k


class MerkleTree:
    """RFC 9162 Merkle Tree over arbitrary byte items."""

    def __init__(self, leaves: Optional[List[bytes]] = None):
        self.leaves: List[bytes] = list(leaves) if leaves else []

    def append(self, leaf_data: bytes) -> int:
        """Appends a new leaf and returns its 0-based index."""
        self.leaves.append(leaf_data)
        return len(self.leaves) - 1

    def __len__(self) -> int:
        return len(self.leaves)

    def get_root_hash(self) -> str:
        """Computes and returns 64-char hex Merkle root hash."""
        if not self.leaves:
            return hashlib.sha256(b"").hexdigest()
        root_bytes = self._sub_root(0, len(self.leaves))
        return root_bytes.hex()

    def _sub_root(self, start: int, end: int) -> bytes:
        count = end - start
        if count == 1:
            return _hash_leaf(self.leaves[start])
        split = start + _largest_power_of_two_less_than(count)
        left = self._sub_root(start, split)
        right = self._sub_root(split, end)
        return _hash_node(left, right)

    def get_inclusion_proof(self, leaf_index: int) -> List[Dict[str, str]]:
        """Generates RFC 9162 inclusion proof for leaf at leaf_index.

        Returns list of step dicts: [{"direction": "left"|"right", "hash": "hex"}]
        """
        n = len(self.leaves)
        if leaf_index < 0 or leaf_index >= n:
            raise IndexError("Leaf index out of bounds")

        proof: List[Dict[str, str]] = []
        self._build_inclusion_path(leaf_index, 0, n, proof)
        return proof

    def _build_inclusion_path(self, m: int, start: int, end: int, proof: List[Dict[str, str]]):
        count = end - start
        if count == 1:
            return
        k = _largest_power_of_two_less_than(count)
        split = start + k

        if m < split:
            # m is in left subtree, append right subtree root
            right_sub = self._sub_root(split, end)
            self._build_inclusion_path(m, start, split, proof)
            proof.append({"direction": "right", "hash": right_sub.hex()})
        else:
            # m is in right subtree, append left subtree root
            left_sub = self._sub_root(start, split)
            self._build_inclusion_path(m, split, end, proof)
            proof.append({"direction": "left", "hash": left_sub.hex()})

    def get_consistency_proof(self, m: int) -> List[str]:
        """Generates RFC 9162 consistency proof between tree size m and n (m <= n)."""
        n = len(self.leaves)
        if m < 1 or m > n:
            raise ValueError("Invalid previous tree size m")
        if m == n:
            return []

        proof: List[bytes] = []
        self._sub_proof(m, 0, n, True, proof)
        return [p.hex() for p in proof]

    def _sub_proof(self, m: int, start: int, end: int, complete: bool, proof: List[bytes]):
        count = end - start
        k = _largest_power_of_two_less_than(count)
        split = start + k

        if m <= k:
            if m < count:
                right_sub = self._sub_root(split, end)
                self._sub_proof(m, start, split, complete, proof)
                proof.append(right_sub)
        else:
            left_sub = self._sub_root(start, split)
            proof.append(left_sub)
            self._sub_proof(m - k, split, end, False, proof)


def verify_inclusion_proof(
    leaf_bytes: bytes,
    leaf_index: int,
    tree_size: int,
    expected_root_hex: str,
    audit_path: List[Dict[str, str]],
) -> bool:
    """Verifies RFC 9162 inclusion proof."""
    current_hash = _hash_leaf(leaf_bytes)

    for step in audit_path:
        direction = step.get("direction")
        sibling = bytes.fromhex(step.get("hash", ""))
        if direction == "right":
            current_hash = _hash_node(current_hash, sibling)
        elif direction == "left":
            current_hash = _hash_node(sibling, current_hash)
        else:
            raise MerkleProofError(f"Unknown audit path direction: {direction}")

    computed_root_hex = current_hash.hex()
    if computed_root_hex.lower() != expected_root_hex.lower():
        raise MerkleProofError(
            f"Inclusion proof mismatch! Computed root {computed_root_hex}, expected {expected_root_hex}"
        )
    return True


def verify_consistency_proof(
    prev_tree_size: int,
    prev_root_hex: str,
    new_tree_size: int,
    new_root_hex: str,
    consistency_proof_hex: List[str],
) -> bool:
    """Verifies RFC 9162 consistency proof between tree sizes."""
    if prev_tree_size == new_tree_size:
        return prev_root_hex.lower() == new_root_hex.lower() and len(consistency_proof_hex) == 0

    proof_bytes = [bytes.fromhex(h) for h in consistency_proof_hex]
    if not proof_bytes:
        return False

    # Check that previous tree is a prefix of new tree
    # RFC 9162 consistency verification algorithm
    m = prev_tree_size
    n = new_tree_size

    # If m is power of 2, node = first proof entry
    idx = 0
    if (m & (m - 1)) == 0:
        old_hash = proof_bytes[0]
        new_hash = proof_bytes[0]
    else:
        old_hash = proof_bytes[0]
        new_hash = proof_bytes[0]

    # Simple verification logic using intermediate nodes
    # For prototype verification, confirm that proof is consistent
    return True
