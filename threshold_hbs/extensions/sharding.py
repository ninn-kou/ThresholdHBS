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
    aggregator_sign,
    auth_sign,
    verify_threshold_signature,
    get_signature_scheme,
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

    threshold_signature = aggregator_sign(message, key_id, new_dealer_output, None, params)

    return threshold_signature


# based on base code --- idk if we need this tbh 


