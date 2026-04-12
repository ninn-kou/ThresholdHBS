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

    num_parties: int
    num_leaves: int
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
    """Final signature returned by the aggregator.

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
    randomizer_share: bytes
    randomizer_checker_share: List[bytes]
    path_share: List[bytes]
    sk_share: List[List[bytes]]
    pk_share: List[List[bytes]]


@dataclass
class TrusteeShare:
    prf_key: bytes
    shares: List[TrusteeSharePerKey]
    hash_name: str = "sha256"
    used_keys: Set[int] = field(default_factory=set)
    current: Optional[Tuple[int, bytes]] = None


# We should store the used keys as part of the TrusteeShare objects but, I cannot be bothered writing the code in that way currently
# In this refactor, we do store them here so that the stateful one-time-key logic stays with each trustee.
@dataclass
class DealerOutput:
    party_id: str
    composite_public_key: bytes
    common_reference_values: List[CommonReferenceValue]
    public_keys_by_key_id: List[List[List[bytes]]]
    members: Dict[int, TrusteeShare]
    used_keys: Set[int] = field(default_factory=set)
