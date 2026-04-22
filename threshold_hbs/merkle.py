from __future__ import annotations

import hashlib
from typing import Any, List, Sequence, Tuple

from threshold_hbs.abstractions.merkle_tree import MerkleTree, MerkleTreeMessages, MerkleTreeSignatures

def build_merkle_tree_signatures(leaf_public_keys: Sequence[Any], hash_name: str = "sha256") -> Tuple[MerkleTree, bytes]:
    """Build a Merkle tree over Lamport public keys.

    Args:
        leaf_public_keys: Ordered list of Lamport public keys, one per leaf.
        hash_name: Name of the hash algorithm used in the Merkle tree.

    Returns:
        A tuple ``(tree, root_public_key)`` where ``tree`` is any internal
        representation chosen by the implementation and ``root_public_key`` is the
        published Merkle root.

    Purpose:
        Commits to all Lamport public keys under one public root key.
    """
    tree = MerkleTreeSignatures(leaf_public_keys, hash_name)
    return tree, tree.root_digest

def build_merkle_tree_messages(messages: List[bytes], hash_name: str = "sha256") -> Tuple[MerkleTree, bytes]:
    tree = MerkleTreeMessages(messages, hash_name)
    return tree, tree.root_digest


def get_auth_path(tree: MerkleTree, key_id: int) -> List[bytes]:
    """Extract the Merkle authentication path for one leaf.

    Args:
        tree: MerkleTree
        key_id: Index of the leaf whose path is requested.

    Returns:
        The ordered list of sibling hashes needed to verify that leaf.

    Purpose:
        Provides the Merkle proof attached to the final signature.
    """
    return tree.auth_path(key_id)


def verify_merkle_path(
    leaf_public_key: Any,
    key_id: int,
    auth_path: Sequence[bytes],
    root_public_key: bytes,
    hash_name: str = "sha256",
) -> bool:
    """Verify that a Lamport public key belongs to the public Merkle tree.

    Args:
        leaf_public_key: Lamport public key reconstructed from the signature.
        key_id: Index of the leaf used for signing.
        auth_path: Authentication path associated with ``key_id``.
        root_public_key: Published Merkle root.
        hash_name: Name of the hash algorithm used in the Merkle tree.

    Returns:
        ``True`` if the leaf authenticates to the supplied root, else ``False``.

    Purpose:
        Checks the Merkle-tree part of the threshold signature.
    """

    def _hash_leaf(public_key: Any) -> bytes:
        h = hashlib.new(hash_name)
        for pair in public_key:
            for hb in pair:
                h.update(hb)
        return h.digest()

    current = _hash_leaf(leaf_public_key)
    pk_id = key_id
    for sibling in auth_path:
        if pk_id % 2 == 0:
            current = MerkleTree.hash_digests(hash_name, current, sibling)
        else:
            current = MerkleTree.hash_digests(hash_name, sibling, current)
        pk_id //= 2

    return current == root_public_key
