from __future__ import annotations
import hashlib
import os
import secrets

"""
A centralized n-of-n threshold hash-based signature prototype.

- Lamport one-time signatures at the leaves.
- A Merkle tree over Lamport public keys.
- A trusted dealer that generates all leaf keys.
- XOR/additive sharing of Lamport secret/public keys across all parties.
- An untrusted aggregator that collects one share from each party.
- Public verification using only the message, final signature, and Merkle root.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
import math
import hashlib

@dataclass
class SystemParameters:
    """Global configuration for the minimal prototype.

    Attributes:
        num_parties: Number of parties in the minimal n-of-n scheme.
        num_leaves: Number of Lamport one-time keys in the Merkle tree.
        hash_name: Hash function name shared by setup, signing, and verification.
        digest_size_bytes: Output size of the message digest used by Lamport signing.
        lamport_element_size_bytes: Byte length of each Lamport secret element.
    """

    num_parties: int
    num_leaves: int
    hash_name: str = "sha256"
    digest_size_bytes: int = 32
    lamport_element_size_bytes: int = 32


@dataclass
class PartyBundle:
    """Trusted-setup output stored by one party.

    Attributes:
        party_id: Stable identifier for the party.
        secret_key_shares_by_key_id: Mapping from key_id to this party's Lamport secret-key share.
        public_key_shares_by_key_id: Mapping from key_id to this party's Lamport public-key share.
        used_key_ids: Local record of which key IDs this party has already used.
    """

    party_id: str
    secret_key_shares_by_key_id: Dict[int, Any]
    public_key_shares_by_key_id: Dict[int, Any]
    used_key_ids: Set[int] = field(default_factory=set)


@dataclass
class DealerOutput:
    """Artifacts produced by the trusted dealer.

    Attributes:
        root_public_key: Merkle root published to verifiers.
        auth_paths_by_key_id: Mapping from key_id to Merkle authentication path.
        party_bundles: Mapping from party_id to per-party shared state.
    """

    root_public_key: bytes
    auth_paths_by_key_id: Dict[int, List[bytes]]
    party_bundles: Dict[str, PartyBundle]


@dataclass
class SignatureShare:
    """One party's response during signing.

    Attributes:
        party_id: Party that produced this share.
        key_id: Lamport/Merkle leaf index being used.
        signature_value_share: Additive share of the Lamport signature values.
        public_key_share: Additive share of the Lamport public key for this leaf.
    """

    party_id: str
    key_id: int
    signature_value_share: Any
    public_key_share: Any


@dataclass
class ThresholdSignature:
    """Final signature returned by the aggregator.

    Attributes:
        key_id: Lamport/Merkle leaf index used for this signature.
        lamport_public_key: Reconstructed Lamport public key for this leaf.
        lamport_signature_values: Reconstructed Lamport signature values.
        auth_path: Merkle authentication path from the leaf to the public root.
    """

    key_id: int
    lamport_public_key: Any
    lamport_signature_values: List[bytes]
    auth_path: List[bytes]

@dataclass
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

@dataclass
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

        # Append append padding to array
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

                parent_digest = self._hash_children(left.digest, right.digest)
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
 
    def _hash_children(self, left: bytes, right: bytes) -> bytes:
        """Hash two child digests together to form a parent digest."""
        h = self._hasher()
        h.update(left)
        h.update(right)
        return h.digest()

def hash_message(message: bytes, hash_name: str = "sha256") -> bytes:
    """Hash a message for Lamport signing.

    Args:
        message: Raw message bytes to be signed.
        hash_name: Name of the hash algorithm to use.

    Returns:
        Digest bytes that will be interpreted bit-by-bit by Lamport signing.

    Purpose:
        Converts an arbitrary-length message into the fixed-length digest used by
        Lamport sign and verify operations.
    """
    h = hashlib.new(hash_name)
    h.update(message)
    return h.digest()


def lamport_generate_keypair(
    digest_size_bytes: int,
    element_size_bytes: int,
    hash_name: str = "sha256",
) -> Tuple[Any, Any]:
    """Generate one Lamport one-time keypair.

    Args:
        digest_size_bytes: Digest length that determines the number of Lamport positions.
        element_size_bytes: Byte length of each secret element.
        hash_name: Name of the hash algorithm used to derive the public key.

    Returns:
        A tuple ``(secret_key, public_key)`` for one Lamport leaf.

    Purpose:
        Creates the one-time signing material stored at one Merkle-tree leaf.
    """
    num_bits = digest_size_bytes * 8
    secret_key: List[List[bytes]] = []
    public_key: List[List[bytes]] = []
    
    for _ in range(num_bits):
        sk0 = secrets.token_bytes(element_size_bytes)
        sk1 = secrets.token_bytes(element_size_bytes)
        pk0 = hash_message(sk0, hash_name)
        pk1 = hash_message(sk1, hash_name)
        secret_key.append([sk0, sk1])
        public_key.append([pk0, pk1])
        
    return secret_key, public_key



def lamport_sign(digest: bytes, secret_key: Any) -> List[bytes]:
    """Produce a Lamport signature for one digest.

    Args:
        digest: Message digest produced by ``hash_message``.
        secret_key: Full Lamport secret key for a single leaf.

    Returns:
        The list of Lamport values revealed for this digest.

    Purpose:
        Selects one secret element per digest bit to form the one-time signature.
    """
    signature_values: List[bytes] = []
    for byte_index, byte_val in enumerate(digest):
        for bit_position in range(7, -1, -1):  
            bit = (byte_val >> bit_position) & 1
            i = byte_index * 8 + (7 - bit_position)
            signature_values.append(secret_key[i][bit])
    return signature_values



def lamport_verify(
    digest: bytes,
    signature_values: Sequence[bytes],
    public_key: Any,
    hash_name: str = "sha256",
) -> bool:
    """Verify a Lamport one-time signature.

    Args:
        digest: Message digest produced by ``hash_message``.
        signature_values: Revealed Lamport values from the signature.
        public_key: Lamport public key for the leaf being verified.
        hash_name: Name of the hash algorithm used in the Lamport construction.

    Returns:
        ``True`` if the Lamport signature is valid, else ``False``.

    Purpose:
        Checks the one-time signature independently of the Merkle tree.
    """
    num_bits = len(digest) * 8
    if len(signature_values) != num_bits:
        return False
 
    for byte_index, byte_val in enumerate(digest):
        for bit_position in range(7, -1, -1):  
            bit = (byte_val >> bit_position) & 1
            i = byte_index * 8 + (7 - bit_position)
            revealed = signature_values[i]
            expected_pk = public_key[i][bit]
            if hash_message(revealed, hash_name) != expected_pk:
                return False
    return True


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


def split_lamport_keypair_into_xor_shares(
    secret_key: Any,
    public_key: Any,
    num_parties: int,
) -> Tuple[List[Any], List[Any]]:
    """Split one Lamport keypair into additive shares.

    Args:
        secret_key: Full Lamport secret key for one leaf.
        public_key: Full Lamport public key for the same leaf.
        num_parties: Number of parties that must jointly reconstruct the leaf data.

    Returns:
        A tuple ``(secret_shares, public_shares)`` where each list has
        ``num_parties`` entries.

    Purpose:
        Converts dealer-owned leaf material into per-party XOR/additive shares for
        the minimal centralized prototype.
    """
    pass


def combine_signature_shares(signature_shares: Sequence[SignatureShare]) -> Tuple[List[bytes], Any]:
    """Combine all party shares into full Lamport signing data.

    Args:
        signature_shares: One share from each party for the same ``key_id``.

    Returns:
        A tuple ``(lamport_signature_values, lamport_public_key)``.

    Purpose:
        Reconstructs the full Lamport signature values and the corresponding full
        Lamport public key from additive shares.
    """
    pass


def dealer_setup(params: SystemParameters, party_ids: Sequence[str]) -> DealerOutput:
    """Run trusted setup for the minimal prototype.

    Args:
        params: Global configuration for the prototype.
        party_ids: Stable identifiers for all participating parties.

    Returns:
        A ``DealerOutput`` containing the public root, per-leaf authentication
        paths, and one share bundle for each party.

    Purpose:
        Generates all Lamport leaf keys, builds the Merkle tree, XOR-splits every
        leaf keypair, and packages the resulting shares for distribution.
    """
    pass


def party_sign_share(
    party_bundle: PartyBundle,
    message: bytes,
    key_id: int,
    params: SystemParameters,
) -> Optional[SignatureShare]:
    """Have one party produce its signing contribution.

    Args:
        party_bundle: Local share bundle owned by the party.
        message: Raw message bytes requested by the aggregator.
        key_id: Leaf index chosen for this signature.
        params: Global system configuration.

    Returns:
        A ``SignatureShare`` if the party agrees to sign, otherwise ``None``.

    Purpose:
        Implements the party-side action in the minimal one-round signing flow.
        A complete implementation should check local policy and ensure the
        ``key_id`` has not been used before.
    """
    pass


def aggregator_sign(
    message: bytes,
    key_id: int,
    party_bundles: Sequence[PartyBundle],
    auth_path: Sequence[bytes],
    params: SystemParameters,
) -> ThresholdSignature:
    """Collect shares from all parties and assemble the final signature.

    Args:
        message: Raw message bytes to be signed.
        key_id: Unused leaf index selected for this signature.
        party_bundles: The current state of all parties that are expected to sign.
        auth_path: Merkle authentication path for the chosen ``key_id``.
        params: Global system configuration.

    Returns:
        A ``ThresholdSignature`` containing the reconstructed Lamport public key,
        reconstructed Lamport signature values, and the authentication path.

    Purpose:
        Coordinates the minimal centralized n-of-n signing flow: request one share
        from every party, combine the shares, and attach the public Merkle proof.
    """
    pass


def verify_threshold_signature(
    message: bytes,
    signature: ThresholdSignature,
    root_public_key: bytes,
    params: SystemParameters,
) -> bool:
    """Verify a final threshold signature.

    Args:
        message: Original message bytes.
        signature: Signature returned by ``aggregator_sign``.
        root_public_key: Public Merkle root generated during trusted setup.
        params: Global system configuration.

    Returns:
        ``True`` if both Lamport verification and Merkle-path verification pass,
        otherwise ``False``.

    Purpose:
        Public verification entry point for the minimal prototype.
    """
    pass


def benchmark_minimal_prototype(
    params: SystemParameters,
    messages: Sequence[bytes],
    dealer_output: DealerOutput,
) -> Dict[str, float]:
    """Benchmark the minimal prototype.

    Args:
        params: Global configuration used in the benchmark.
        messages: Workload of messages to sign and verify.
        dealer_output: Setup artifacts returned by ``dealer_setup``.

    Returns:
        A dictionary of benchmark names to measured values.

    Purpose:
        Provides one place to time setup, signing, verification, and output sizes
        without mixing benchmarking code into the core protocol logic.
    """
    pass
