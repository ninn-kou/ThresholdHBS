"""Extension 1: k-of-n via k-of-k subtrees / sharding.

Recommended responsibilities:
- coalition list (CL) representation
- KeyID allocation per coalition
- coalition-aware signing coordinator
"""

import time
from typing import Any, Dict, List, Optional, Sequence, Tuple
from itertools import combinations
import secrets
import os
import functools

from ..models import (
    CommonReferenceValue,
    DealerOutput,
    SystemParameters,
    ThresholdSignature,
    TrusteeShare,
    TrusteeSharePerKey,
    CoalitionGroup,
    ShardingState
)

from ..protocol import (
    KeyReuseError,
    SigningRefusedError,
    auth_sign,
    verify_threshold_signature,
)

from ..lamport import (
    lamport_generate_keypair,
    lamport_sign
)

from ..merkle import (
    build_merkle_tree,
    get_auth_path
)

from ..sharing import (
    estimate_crv_size_bytes,
    estimate_signature_size_bytes,
    key_id_to_bytes,
    prf_hmac,
    signing_digest_bytes,
    xor
)

def generate_coalitions(    
    params: SystemParameters,
    party_ids: Sequence[str]
) -> List[CoalitionGroup]:  
    
    """generate coalition groups based on the k_value from available parties

    Args: 
        params: .threshold_k for coalition group size, .party_ids for available parties
    
    Returns: 
        A list containing all possible coalition group combinations

    """
    # sanity checks
    if party_ids and len(party_ids) != params.num_parties:
        raise ValueError("len(party_ids) must equal params.num_parties when party_ids is provided")

    if params.threshold_k > len(party_ids):
        raise ValueError("Threshold value cannot be larger than existing number of parties")


    coalition_groups = []
    threshold_k = params.threshold_k

    # generate class combination based on threshold_k
    for combination in combinations(party_ids, threshold_k):
        new_coalition = CoalitionGroup(
            group_members=combination,
            assigned_key_ids=[]   # not yet assigned? cuz this will be done in another function? 
        )

        coalition_groups.append(new_coalition)

    return coalition_groups


def assign_keys_to_all_coalitions(
    params: SystemParameters,
    coalition_groups: List[CoalitionGroup]
) -> ShardingState:
    
    """assign keys to all coalition groups, save to each coalition group and output sharding state
    
    Args: 
        params: .num_leaves to know the number of (private key, public key) pairs available
        coalition_groups: all coalition groups
                
    Returns: 
        One dictionary that lists all keys assigned to each coalition group
        One dictionary that lists the corresponding coalition group to each (private key, public) key pair

    """

    key_num = params.num_leaves 
    
    coalition_to_keys = {group.group_members: group for group in coalition_groups}
    key_to_coalition = {}

    for key_id in range(key_num):
        # use modulo to alternatingly assign keys to coalition groups 
        group_index = key_id % len(coalition_groups)    
        selected_group = coalition_groups[group_index]
        dict_key = selected_group.group_members

        selected_group.assigned_key_ids.append(key_id)
        # map key to their corresponding coalition group
        key_to_coalition[key_id] = dict_key

    return ShardingState(
        coalition_map=coalition_to_keys,
        key_to_coalition=key_to_coalition
    )


def select_signing_coalition_and_key(
    coalition_groups: List[CoalitionGroup]
) -> tuple[CoalitionGroup, int]:    # should it just return two terms instead of a tuple?

    """select a coalition group, select an available key from it to assign a pair of key to it

    Args: 
        coalition_groups: all coalition groups
    
    Returns: 
        A tuple of: 
        - The selected coalition group
        - The selected key_id for the selected coalition group

    Purpose: 
        Select a valid coalition for signing and reserve one of its unused key id for this signing session
        -> selected key_id in .assigned_key_ids but not in used_key_ids
    """

    for group in coalition_groups:
        # find a coalition group that has at least one unused assigned key
        for key in group.assigned_key_ids:
            # find unused key
            if key not in group.used_key_ids: 
                group.used_key_ids.add(key)
                return (group, key)

    raise ValueError("No available coalition/key pair remains")


# based on dealer_setup - did not change major logic, only the prf related parts
def dealer_setup_ext1(      
    params: SystemParameters,
    party_ids: Sequence[str]
) -> tuple[DealerOutput, ShardingState]: 
    
    """Extenion 1 setup based on full project impelemntation with PRF-based model
       
       Call dealer_setup_full() to perform the base full-prject setup --- im not too sure about that rn? cuz the dealer_setup rn is a hybrid or smt?

    Args: 
        params: global system configuration 

    Returns: 
        A tuple of:
        - DealerOutput: setup (merkle root, auth paths, per-party PRF-based bundles, and dealer-held shares)
        - ShardingState: coalition-to-key and key-to-coalition assignments
    
    Purpose: 
        Extenion 1 setup:
        - call dealer_setup_full() for the base lamport/merkle/PRF setup
        - generate coalition groups
        - assign key_ids to coalition groups
        - return both the base DealerOutput + ShardingState

    """

    # sanity check 
    if party_ids and len(party_ids) != params.num_parties:
        raise ValueError("len(party_ids) must equal params.num_parties when party_ids is provided")
    

    # coalition group setup
    coalition_groups = generate_coalitions(params, party_ids)
    sharding_state = assign_keys_to_all_coalitions(params, coalition_groups) 

    # based on existing dealer_setup
    secret_keys = []
    public_keys = []

    for key_id in range(params.num_leaves):
        secret_key, public_key = lamport_generate_keypair(
            params.digest_size_bytes,
            params.lamport_element_size_bytes,
            params.hash_name,
        )

        secret_keys.append(secret_key)
        public_keys.append(public_key)

    common_reference_values: List[CommonReferenceValue | None] = [None] * params.num_leaves

    merkle_tree, composite_public_key = build_merkle_tree(public_keys, params.hash_name)

    # distribute prf key to parties
    prf_keys: List[bytes] = [secrets.token_bytes(32) for _ in range(params.num_parties)]

    # create all parties
    trustees = [] 

    for index, party in enumerate(party_ids): 
        trustees.append(TrusteeShare(
            prf_key=prf_keys[index],
            shares=[],
            party_id=party,
            hash_name=params.hash_name
        ))
    
     # Compute the shares and common reference value
    for key_id, secret_key in enumerate(secret_keys):
        public_key = public_keys[key_id]
        key_id_bytes = key_id_to_bytes(key_id)
        path: List[bytes] = get_auth_path(merkle_tree, key_id)
        randomizer: bytes = os.urandom(params.digest_size_bytes)
        chk: List[bytes] = []

        chk_shares: List[List[bytes]] = []
        randomizer_shares: List[bytes] = []
        path_shares: List[List[bytes]] = []
        secret_key_shares: List[List[List[bytes]]] = []
        public_key_shares: List[List[List[bytes]]] = []

        # find which coalition group does the current key_id belong to
        assigned_coalition_group = sharding_state.key_to_coalition[key_id]

        # split key values among coalition group members
        for member in assigned_coalition_group:

            # find corresponding trustee 
            trustee = next((t for t in trustees if t.party_id == member), None) # realistically would not be None
            
            if trustee is None:
                raise ValueError(f"Trustee not found for party_id {member}")
            
            prf_seed = trustee.prf_key
            chk.append(prf_hmac(prf_seed, "AUTH", key_id_bytes + randomizer, params.digest_size_bytes))
            randomizer_shares.append(prf_hmac(prf_seed, "R", key_id_bytes, params.digest_size_bytes))

            coalition_size = len(assigned_coalition_group)

            chk_share_raw = prf_hmac(prf_seed, "CHK", key_id_bytes, params.digest_size_bytes * coalition_size)
            chk_split = []

            for i in range(coalition_size):
                chk_split.append(chk_share_raw[(i * params.digest_size_bytes):((i + 1) * params.digest_size_bytes)])

            chk_shares.append(chk_split)

            # Computing the path shares
            ps_raw = prf_hmac(prf_seed, "PATH", key_id_bytes, sum(map(lambda x: len(x), path)))
            ps_split = []
          
            i, j = 0, 0
            while i < len(ps_raw):
                l = len(path[j])
                ps_split.append(ps_raw[i:i + l])
                j += 1
                i += l

            path_shares.append(ps_split)

            # secret and public key
            member_secret_key_share = []
            member_public_key_share = []

            for i in range(len(secret_key)): 
                member_secret_key_share.append([])
                member_public_key_share.append([])

                for j in range(len(secret_key[0])):
                    member_secret_key_share[i].append(prf_hmac(
                            prf_seed,
                            "CHAIN",
                            key_id_bytes + i.to_bytes(4, "big") + j.to_bytes(2, "big"),
                            params.lamport_element_size_bytes,
                        ))
                    member_public_key_share[i].append(prf_hmac(
                            prf_seed,
                            "PUBLIC",
                            key_id_bytes + i.to_bytes(4, "big") + j.to_bytes(2, "big"),
                            len(public_key[i][j]),
                        ))
            
            secret_key_shares.append(member_secret_key_share)
            public_key_shares.append(member_public_key_share)

            randomizer_share = randomizer_shares[-1]
            randomizer_checker_share = chk_shares[-1]
            path_share = path_shares[-1]
            sk_share = secret_key_shares[-1]
            pk_share = public_key_shares[-1]

            # save it to the trusteeperkey
            member_share = TrusteeSharePerKey(
                randomizer_share= randomizer_share,
                randomizer_checker_share= randomizer_checker_share,
                path_share= path_share,
                sk_share= sk_share,
                pk_share= pk_share,
                key_id=key_id
            )
            
            # save to trustee 
            trustee.shares.append(member_share)

        crv_secret_key = [[bytes(value) for value in pair] for pair in secret_key]
        crv_public_key = [[bytes(value) for value in pair] for pair in public_key]

        for i in range(len(secret_key)):
            for j in range(len(secret_key[0])):
                for secret_key_share in secret_key_shares:
                    crv_secret_key[i][j] = xor(crv_secret_key[i][j], secret_key_share[i][j])
                for public_key_share in public_key_shares:
                    crv_public_key[i][j] = xor(crv_public_key[i][j], public_key_share[i][j])

        crv = CommonReferenceValue(
            randomizer=functools.reduce(lambda x, y: xor(x, y), randomizer_shares, randomizer),
            path=functools.reduce(lambda x, y: [xor(x_elem, y_elem) for x_elem, y_elem in zip(x, y)], path_shares, path),
            randomizer_checker=functools.reduce(lambda x, y: [xor(x_elem, y_elem) for x_elem, y_elem in zip(x, y)], chk_shares, chk),
            secret_key=crv_secret_key,
            public_key=crv_public_key,
        )

        common_reference_values[key_id] = crv

    
    dealer_output = DealerOutput(
        party_id="",    
        composite_public_key=composite_public_key,
        common_reference_values=common_reference_values,  # type: ignore[arg-type]
        members={trustee.party_id: trustee for trustee in trustees},
        public_keys_by_key_id=public_keys,
    )

    return (dealer_output, sharding_state)   

    # refractor this pls its so long omg


# exactly the same as base code --- modified included functions that's why its here
def aggregator_sign_ext1(
    message: bytes,
    key_id: int,
    party_bundles: Sequence[Any] | DealerOutput,
    auth_path: Optional[Sequence[bytes]] = None,
    params: Optional[SystemParameters] = None,
) -> ThresholdSignature:

    if params is None:
        raise ValueError("params is required")

    if isinstance(party_bundles, DealerOutput):
        party_bundle = party_bundles
    elif len(party_bundles) == 1 and isinstance(party_bundles[0], DealerOutput):
        party_bundle = party_bundles[0]
    else:
        raise TypeError(
            "In the current minimal prototype, party_bundles must be a DealerOutput or a length-1 sequence containing one."
        )

    result = party_sign_share_ext1(party_bundle, message, key_id, params)
    if result is None:
        raise SigningRefusedError("party_sign_share returned None")
    (randomizer, path, z) = result

    if auth_path is not None and list(auth_path) != list(path):
        raise ValueError("provided auth_path does not match the reconstructed path")

    lamport_public_key = _reconstruct_lamport_public_key_ext1(party_bundle, key_id)

    return ThresholdSignature(
        key_id=key_id,
        randomizer=randomizer,
        lamport_public_key=lamport_public_key,
        lamport_signature_values=z,
        auth_path=path,
    )


# based on base code - same except prf lookup
def party_sign_share_ext1(
    party_bundle: DealerOutput,
    message: bytes,
    key_id: int,
    params: SystemParameters,
) -> Optional[Tuple[bytes, List[bytes], List[bytes]]]:
    
    if key_id in party_bundle.used_keys:
        raise KeyReuseError(f"key_id {key_id} has already been used by this party bundle")
    party_bundle.used_keys.add(key_id)

    randomizer = party_bundle.common_reference_values[key_id].randomizer
    chk = list(party_bundle.common_reference_values[key_id].randomizer_checker)

    # simplified as the key_id is not needed in this case - same logic here
    for trustee_share in party_bundle.members.values():
        (r_share, chk_share) = sign_1_ext1(trustee_share, key_id, message)
        randomizer = xor(randomizer, r_share)
        chk = list(map(lambda z: xor(z[0], z[1]), zip(chk, chk_share)))

    h = signing_digest_bytes(message, key_id, randomizer, params.digest_size_bytes, params.hash_name)
    z = lamport_sign(h, party_bundle.common_reference_values[key_id].secret_key)
    path = list(party_bundle.common_reference_values[key_id].path)

    # as members: [str, TrusteeShare]
    for i, trustee_share in enumerate(party_bundle.members.values()):
        (path_share, z_share) = sign_2_ext1(trustee_share, key_id, message, randomizer, chk[i])
        z = list(map(lambda x: xor(x[0], x[1]), zip(z, z_share)))
        path = list(map(lambda x: xor(x[0], x[1]), zip(path, path_share)))

    return (randomizer, path, z)

# based on base code, changed the way it fetches for common_reference_values, since not every party is assigned to this key_id
def _reconstruct_lamport_public_key_ext1(party_bundle: DealerOutput, key_id: int) -> List[List[bytes]]:
    lamport_public_key = [[bytes(value) for value in pair] for pair in party_bundle.common_reference_values[key_id].public_key]

    for trustee_share in party_bundle.members.values():
        # find corresponding key share in trustee
        trustee_key_share = None
        for share in trustee_share.shares: 
            if share.key_id == key_id:
                trustee_key_share = share
                break
        
        if trustee_key_share is None:
            raise SigningRefusedError(f"Trustee has no share for key_id {key_id}")
        
        lamport_public_key = [
            [xor(lamport_public_key[i][j], trustee_key_share.pk_share[i][j]) for j in range(len(lamport_public_key[i]))]
            for i in range(len(lamport_public_key))
        ]

    return lamport_public_key


# based on base code, changed the return part as again shares not include all keys for ext1
def sign_1_ext1(share: TrusteeShare, key_id: int, message: bytes) -> Tuple[bytes, List[bytes]]:

    if key_id in share.used_keys:
        raise KeyReuseError(f"key_id {key_id} has already been used by this trustee")
    if share.current is not None:
        raise SigningRefusedError("trustee already has a pending signing request")

    share.used_keys.add(key_id)
    share.current = (key_id, message)

    # changed
    trustee_share = None
    for term in share.shares:
        if term.key_id == key_id:
            trustee_share = term
            break
    
    if trustee_share is None: 
        raise SigningRefusedError(f"Trustee has no share for key_id {key_id}")
    
   
    return (trustee_share.randomizer_share, trustee_share.randomizer_checker_share)

# 
def sign_2_ext1(share: TrusteeShare, key_id: int, message: bytes, randomizer: bytes, randomizer_checker: bytes) -> Tuple[List[bytes], List[bytes]]:
    if share.current is None:
        raise SigningRefusedError("trustee has no pending signing request")

    current_key_id, current_message = share.current
    share.current = None

    if current_key_id != key_id or current_message != message:
        raise SigningRefusedError("mismatched second-round request")

    if auth_sign(share, key_id, randomizer, randomizer_checker):
        # changed -- same change as sign_1
        trustee_share = None
        for term in share.shares:
            if term.key_id == key_id:
                trustee_share = term
                break

        if trustee_share is None: 
            raise SigningRefusedError(f"Trustee has no share for key_id {key_id}")
    
        digest_size_bytes = len(trustee_share.sk_share) // 8
        h = signing_digest_bytes(message, key_id, randomizer, digest_size_bytes, share.hash_name)
        return (trustee_share.path_share, lamport_sign(h, trustee_share.sk_share))
    else:
        raise SigningRefusedError("trustee refused to sign because the randomizer check failed")


# wrapper for aggregator_sign
def coalition_signature_scheme(
    message: bytes,
    dealer_output: DealerOutput,
    params: SystemParameters,
    sharding_state: ShardingState
) -> ThresholdSignature:    

    """
    k-of-k scheme within the coalition group using full-project PRF-derived shares

    Args: 
        message: Raw message bytes to be signed.
        key_id: Unused leaf index selected for this signature.
        coalition: Chosen coalition group for signing
        party_bundles: Mapping from party_id to each party's PRF-based local state
        dealer_output: Full-project setup output containing Merkle data and dealer-held shares
        params: Global system configuration.
    
    Returns: 
        A ``ThresholdSignature`` containing the reconstructed Lamport public key,
        reconstructed Lamport signature values, and the authentication path.


    Purpose: 
        - Collect PRF-derived signing contributions from the members of the selected coalition group for the chosen key_id
        - Combine results with the dealer-held share to reconstruct the lamport signature data
        - Attach result with Merkle authentication path to produce the final thresholdSignature

    """
    # extract coalition groups
    coalition_groups = list(sharding_state.coalition_map.values())

    # select valid coalition group and key 
    selected_group, key_id = select_signing_coalition_and_key(coalition_groups)

    # filter existing dealer_output to only contain members from selected coalition group
    group_members = {}

    for name, trustee in dealer_output.members.items():
        if name in selected_group.group_members: 
            group_members[name] = trustee

    # reassign
    new_dealer_output = DealerOutput(
        party_id=dealer_output.party_id,    # i still dk why it exist tbh -- can we take it out
        composite_public_key=dealer_output.composite_public_key,
        common_reference_values=dealer_output.common_reference_values,
        public_keys_by_key_id=dealer_output.public_keys_by_key_id,
        members=group_members,
        used_keys=dealer_output.used_keys
    )   

    # update used key into dealer_output as well - not sure if its needed tho cuz its tracked in coalition group already
    # new_dealer_output.used_keys.add(key_id)

    threshold_signature = aggregator_sign_ext1(message, key_id, new_dealer_output, None, params)

    return threshold_signature


# based on base code --- idk if we need this tbh 
def benchmark_ext1(
    params: SystemParameters,
    messages: Sequence[bytes],
    dealer_output: DealerOutput,
    sharding_state: ShardingState
) -> Dict[str, float]:
    
    if len(messages) > params.num_leaves:
        raise ValueError("Need at least as many leaves as messages to benchmark")

    sign_start = time.perf_counter()
    signatures = [
        # only changed aggregator_sign to coalition_signature_scheme
        coalition_signature_scheme(message, dealer_output, params, sharding_state)
        for message in enumerate(messages)
    ]
    sign_total_s = time.perf_counter() - sign_start
    
    # verification 
    verify_start = time.perf_counter()
    verified = 0
    for message, signature in zip(messages, signatures):
        if verify_threshold_signature(message, signature, dealer_output.composite_public_key, params):
            verified += 1
    verify_total_s = time.perf_counter() - verify_start

    average_signature_size_bytes = 0.0
    if signatures:
        average_signature_size_bytes = sum(estimate_signature_size_bytes(signature) for signature in signatures) / len(signatures)

    return {
        "sign_total_s": sign_total_s,
        "verify_total_s": verify_total_s,
        "sign_avg_s": sign_total_s / len(messages) if messages else 0.0,
        "verify_avg_s": verify_total_s / len(messages) if messages else 0.0,
        "average_signature_size_bytes": float(average_signature_size_bytes),
        "crv_size_bytes": float(estimate_crv_size_bytes(dealer_output.common_reference_values)),
        "signatures_verified": float(verified),
    }

