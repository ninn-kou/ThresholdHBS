from __future__ import annotations

import hashlib
import math
from typing import Any, List, Sequence, Tuple


class MerkleNode:
    """A single node in the Merkle tree.

    Leaf nodes store the hash of a Lamport public key.
    Internal nodes store the hash of their two children's digests.
    """

    def __init__(self, digest: bytes, left: "MerkleNode | None" = None, right: "MerkleNode | None" = None) -> None:
        self.digest: bytes = digest
        self.left: MerkleNode | None = left
        self.right: MerkleNode | None = right

    def is_leaf(self) -> bool:
        return self.left is None and self.right is None


class MerkleTree:
    """A complete binary Merkle tree built over an ordered list of Lamport public keys.

    The tree is always padded to the next power of two so every internal node
    has exactly two children, which keeps the authentication-path logic simple.
    Padding leaves are filled with the zero digest so they never collide with
    real leaves.

    Attributes:
        hash_name:   Name of the hashlib algorithm used throughout the tree.
        n_real:      Number of real (non-padding) leaves.
        n_leaves:    Total leaves including padding (always a power of two).
        leaves:      The leaf-level MerkleNode objects, real then padding.
        root:        The root MerkleNode whose digest is the public Merkle key.
    """

    def __init__(self, leaf_public_keys: Sequence[Any], hash_name: str = "sha256") -> None:
        if not leaf_public_keys:
            raise ValueError("At least one leaf public key is required.")

        self.hash_name = hash_name
        self.n_real = len(leaf_public_keys)

        self.n_leaves = 1 << math.ceil(math.log2(max(self.n_real, 2)))

        # Build leaves array
        self.leaves: List[MerkleNode] = []
        for pk in leaf_public_keys:
            self.leaves.append(MerkleNode(self._hash_public_key(pk)))

        # Append padding to array
        zero = bytes(self._digest_size())
        for _ in range(self.n_leaves - self.n_real):
            self.leaves.append(MerkleNode(zero))

        # Build the tree bottom-up while storing every level store every level
        # _levels is a 2D array where each inner list is one level of the tree:
        #
        #   _levels[0] = [leaf0, leaf1, leaf2, leaf3]        ← leaf level
        #   _levels[-1] = [root]                              ← root level
        #
        # Within each level, nodes sit at consecutive even/odd index pairs:
        #   _levels[k][i] and _levels[k][i^1] are always siblings,
        #   with their parent at _levels[k+1][i//2].
        self._levels: List[List[MerkleNode]] = [self.leaves]
        current_level = self.leaves

        while len(current_level) > 1:
            next_level: List[MerkleNode] = []
            for i in range(0, len(current_level), 2):
                # left child is in even index, right child is in odd index
                left = current_level[i]
                right = current_level[i + 1]

                parent_digest = MerkleTree.hash_digests(self.hash_name, left.digest, right.digest)
                next_level.append(MerkleNode(parent_digest, left, right))
            self._levels.append(next_level)
            current_level = next_level

        self.root: MerkleNode = current_level[0]

    # public helpers
    @property
    def root_digest(self) -> bytes:
        """The published Merkle root / public key."""
        return self.root.digest

    def auth_path(self, key_id: int) -> List[bytes]:
        """Return the ordered list of sibling digests from leaf to root.

        The list is ordered bottom-up (leaf sibling first, root's child last),
        which matches the order needed by :func:`verify_merkle_path`.

        Args:
            key_id: Index of the leaf (0-based).

        Returns:
            List of sibling node digests, one per tree level (excluding root).
        """
        if not (0 <= key_id < self.n_real):
            raise IndexError(f"key_id {key_id} out of range [0, {self.n_real}).")

        path: List[bytes] = []
        pk_id = key_id
        for level in self._levels[:-1]:
            if pk_id % 2 == 0:
                sibling_pk_id = pk_id + 1  # current is left child, sibling is to the right
            else:
                sibling_pk_id = pk_id - 1  # current is right child, sibling is to the left
            path.append(level[sibling_pk_id].digest)
            pk_id //= 2
        return path

    # private helpers
    def _hasher(self):
        return hashlib.new(self.hash_name)

    def _digest_size(self) -> int:
        return self._hasher().digest_size

    def _hash_public_key(self, public_key: Any) -> bytes:
        """
            Serialize a Lamport public key and hash it to produce a leaf digest.
        """
        h = self._hasher()
        for pair in public_key:
            for hash_bytes in pair:
                h.update(hash_bytes)

        return h.digest()

    # helper function to combine 2 hash digests
    @staticmethod
    def hash_digests(hash_name: str, left: bytes, right: bytes) -> bytes:
        """Hash two digests together to form a parent digest."""
        h = hashlib.new(hash_name)
        h.update(left)
        h.update(right)
        return h.digest()


def build_merkle_tree(leaf_public_keys: Sequence[Any], hash_name: str = "sha256") -> Tuple[MerkleTree, bytes]:
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
    tree = MerkleTree(leaf_public_keys, hash_name)
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
