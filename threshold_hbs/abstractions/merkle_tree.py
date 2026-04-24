from __future__ import annotations

import hashlib
import math
from abc import ABC, abstractmethod
from typing import Any, List, Sequence


class MerkleNode:
    def __init__(self, digest: bytes, left: "MerkleNode | None" = None, right: "MerkleNode | None" = None) -> None:
        self.digest: bytes = digest
        self.left: MerkleNode | None = left
        self.right: MerkleNode | None = right

    def is_leaf(self) -> bool:
        return self.left is None and self.right is None


class MerkleTree(ABC):
    def __init__(self, leaves_data: Sequence[Any], hash_name: str = "sha256") -> None:
        if not leaves_data:
            raise ValueError("At least one leaf is required to build the tree.")

        self.hash_name = hash_name
        self.n_real = len(leaves_data)
        self.n_leaves = 1 << math.ceil(math.log2(max(self.n_real, 2)))

        # Build leaves array using the subclass's specific hashing implementation
        self.leaves: List[MerkleNode] = []
        for data in leaves_data:
            leaf_digest = self.hash_leaf_data(data)
            self.leaves.append(MerkleNode(leaf_digest))

        # Append padding to array using empty/zero bytes
        zero = bytes(hashlib.new(self.hash_name).digest_size)
        for _ in range(self.n_leaves - self.n_real):
            self.leaves.append(MerkleNode(zero))

        # Build the tree bottom-up
        self._levels: List[List[MerkleNode]] = [self.leaves]
        current_level = self.leaves

        while len(current_level) > 1:
            next_level: List[MerkleNode] = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1]

                parent_digest = MerkleTree.hash_digests(self.hash_name, left.digest, right.digest)
                next_level.append(MerkleNode(parent_digest, left, right))
            self._levels.append(next_level)
            current_level = next_level

        self.root: MerkleNode = current_level[0]

    @abstractmethod
    def hash_leaf_data(self, data: Any) -> bytes:
        pass

    @property
    def root_digest(self) -> bytes:
        return self.root.digest

    # Collect sibling hashes at each level to reconstruct the path to the root
    def auth_path(self, key_id: int) -> List[bytes]:
        if not (0 <= key_id < self.n_real):
            raise IndexError(f"key_id {key_id} out of range [0, {self.n_real}).")

        path: List[bytes] = []
        pk_id = key_id
        for level in self._levels[:-1]:
            if pk_id % 2 == 0:
                sibling_pk_id = pk_id + 1  
            else:
                sibling_pk_id = pk_id - 1  
            path.append(level[sibling_pk_id].digest)
            pk_id //= 2
        return path

    @staticmethod
    def hash_digests(hash_name: str, left: bytes, right: bytes) -> bytes:
        h = hashlib.new(hash_name)
        h.update(left)
        h.update(right)
        return h.digest()


class MerkleTreeSignatures(MerkleTree):
    # Hash Lamport public key into a single digest
    def hash_leaf_data(self, data: Any) -> bytes:
        h = hashlib.new(self.hash_name)
        for pair in data:
            for hash_bytes in pair:
                h.update(hash_bytes)
        return h.digest()


class MerkleTreeMessages(MerkleTree):
    # Hash message bytes directly to form leaf node
    def hash_leaf_data(self, data: Any) -> bytes:
        h = hashlib.new(self.hash_name)
        h.update(data)
        return h.digest()
