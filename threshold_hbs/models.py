from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from threshold_hbs.abstractions.signature_scheme import SignatureScheme

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
    signature_scheme: SignatureScheme 
    num_parties: int
    num_leaves: int
    threshold_k: int | None = None 
    hash_name: str = "sha256"
    digest_size_bytes: int = 32
    lamport_element_size_bytes: int = 32
    batching: int = 3


@dataclass
class CommonReferenceValue:
    randomizer: bytes
    randomizer_checker: List[bytes]
    path: List[bytes]
    secret_key: List[List[bytes]]
    public_key: List[List[bytes]]
    

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
    signature: bytes
    randomizer: bytes
    path: List[bytes]


@dataclass
class ThresholdSignature:
    """Final signature returned by the aggregator to the verifier.

    Attributes:
        key_id: Lamport/Merkle leaf index used for this signature.
        randomizer: Randomizer used in the stateful-HBS-style signing digest.
        lamport_public_key: Reconstructed Lamport public key for this leaf.
        lamport_signature_values: Reconstructed Lamport signature values.
        auth_path: Merkle authentication path from the leaf to the public root.
    """

    key_id: int
    randomizer: bytes
    lamport_public_key: Any
    lamport_signature_values: List[bytes]
    auth_path: List[bytes]


@dataclass
class TrusteeSharePerKey: 
    """Stores per-key PRF-derived shares for a trustee."""

    randomizer_share: bytes
    randomizer_checker_share: List[bytes]
    path_share: List[bytes]    
    sk_share: List[List[bytes]]
    pk_share: List[List[bytes]]   
    key_id: int | None = None


@dataclass
class TrusteeShare:
    """Stores a trustee's PRF key, per-key shares, and signing state."""

    prf_key: bytes      
    shares: List[TrusteeSharePerKey]    
    party_id: str | None = None
    hash_name: str = "sha256"
    used_keys: Set[int] = field(default_factory=set)
    current: Optional[Tuple[int, bytes]] = None   


@dataclass
class DealerOutput:
    """Stores global setup data including CRVs, public keys, and trustee states."""
    party_id: str       
    composite_public_key: bytes    
    common_reference_values: List[CommonReferenceValue]     
    public_keys_by_key_id: List[List[List[bytes]]]  
    members: Dict[str, TrusteeShare]  
    # Tracks used key_ids to prevent reuse
    used_keys: Set[int] = field(default_factory=set)

@dataclass
class CoalitionGroup:
    """Represents a coalition of parties and the key_ids assigned to it."""

    group_members: tuple[str, ...] 
    assigned_key_ids: List[int]
    used_key_ids: Set[int] = field(default_factory=set)

@dataclass
class ShardingState:
    """Stores mappings between coalition groups and key_ids for signing."""
    coalition_map: Dict[tuple[str, ...], CoalitionGroup] 
    key_to_coalition: Dict[int, tuple[str, ...]]   


@dataclass
class BatchSignature:
    """Stores a batch signature with message index, message path, and root signature."""
    message_index: int
    message_auth_path: List[bytes]
    threshold_signature: ThresholdSignature


@dataclass
class UpperTreeSignature:
    """Represents a signature in the upper Merkle tree layer."""
    key_id: int
    bottom_root: bytes
    public_key: bytes
    randomizer: bytes
    signature_values: List[bytes]
    auth_path: List[bytes]


@dataclass
class HyperTreeSignature:
    """Combines batch and upper-tree signatures into a hypertree signature."""
    batch_signature: BatchSignature
    upper_tree_signature: UpperTreeSignature

