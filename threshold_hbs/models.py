from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple


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
    # ext 1
    num_parties: int
    num_leaves: int
    threshold_k: int | None = None 
    hash_name: str = "sha256"
    digest_size_bytes: int = 32
    lamport_element_size_bytes: int = 32



@dataclass
class CommonReferenceValue:
    randomizer: bytes
    randomizer_checker: List[bytes]
    path: List[bytes]
    secret_key: List[List[bytes]]
    public_key: List[List[bytes]]
    
# each CommonReferenceValue is one leaf on the Merkle tree
# one pair of lamport key - (public, private)
# path - merkle authentication path for that leaf
# the lists for pk and sk is: outer - position index, inner - 0 and 1 secret value of that position


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

# what this party returns when asked to sign - signing contribution
    
# is it xor or is it prf rn?




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

# lamport signature values - revealed lamport elements


@dataclass
class TrusteeSharePerKey: 

    randomizer_share: bytes
    randomizer_checker_share: List[bytes]
    path_share: List[bytes]     # questionable, fr not sure ????
    sk_share: List[List[bytes]]
    pk_share: List[List[bytes]]   

    # should have it for ext 1 implementation
    key_id: int | None = None

# one trustee's stored shares for one key_id
# should have a key_id unless the position of it in trusteeshare corresponds to its key_id??? 



@dataclass
class TrusteeShare:
    prf_key: bytes      # prf seed
    shares: List[TrusteeSharePerKey]    # this should not exist in the full implementation with will prf right? --- ig i can keep it??
    # modify - it needs to have party_id?
    party_id: str | None = None
    hash_name: str = "sha256"
    used_keys: Set[int] = field(default_factory=set)
    current: Optional[Tuple[int, bytes]] = None     # still dk what is this


# We should store the used keys as part of the TrusteeShare objects but, I cannot be bothered writing the code in that way currently
# In this refactor, we do store them here so that the stateful one-time-key logic stays with each trustee.
@dataclass
class DealerOutput:
    party_id: str       # ? 
    composite_public_key: bytes     # global public tree root
    common_reference_values: List[CommonReferenceValue]     # all the leaves in merkle tree
    public_keys_by_key_id: List[List[List[bytes]]]  # key_id, positions, 0/1 at that position
    # members: Dict[int, TrusteeShare]    # think of it as all parties --- 
    # members: Dict[str, TrusteeShare]  
    used_keys: Set[int] = field(default_factory=set)


# extension 1 class
@dataclass
class CoalitionGroup:
    """
    stores coalition groups
    """
    group_members: tuple[str, ...] 
    assigned_key_ids: List[int]
    used_key_ids: Set[int] = field(default_factory=set)


@dataclass
class ShardingState:
    coalition_map: Dict[tuple[str, ...], CoalitionGroup]   # given coalition group, what keys are assigned to them
    key_to_coalition: Dict[int, tuple[str, ...]]    # given key, which is the corresponding coalition group




