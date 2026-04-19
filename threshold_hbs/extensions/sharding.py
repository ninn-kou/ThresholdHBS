"""Extension 1: k-of-n via k-of-k subtrees / sharding.

Recommended responsibilities:
- coalition list (CL) representation
- KeyID allocation per coalition
- coalition-aware signing coordinator
"""

from typing import Iterable, List, Sequence
from itertools import combinations

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
    dealer_setup
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

    if threshold_k > len(party_ids):
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
    
    coalition_to_keys = []
    key_to_coalition = []

    for key_id in range(key_num):
        # use modulo to alternatingly assign keys to coalition groups 
        group_index = key_id % len(coalition_groups)    
        # add assigned key_id
        selected_group = coalition_groups[group_index]
        selected_group.assigned_key_ids.append(key_id)   
        dict_key = selected_group.group_members

        # check if the group already exists in the dictionary
        if dict_key in coalition_to_keys:
            coalition_to_keys[dict_key].assigned_key_ids.append(key_id)
            
        else: # does not exist, then add it in
            coalition_to_keys[dict_key] = selected_group
            coalition_to_keys[dict_key].assigned_key_ids.append(key_id)

        # construct ShardingState
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

    selected_key = None

    for group in coalition_groups:
        # find a coalition group that has at least one unused assigned key
        usable_keys = []
        if len(group.assigned_key_ids) > len(group.used_key_ids): 
            for key in group.assigned_key_ids:
                # find unused key
                if key not in group.used_key_ids: 
                    usable_keys.append(key)
        
        if len(usable_keys) >= 1:
            # if usable_keys not empty, select the first key to use
            selected_key = usable_keys[0]
            group.used_key_ids.append(selected_key)

        return [group, selected_key]


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

    # call existing dealer for basic setup
    # dealer_setup_output = dealer_setup(params, party_ids)

    # write my own ext 1 code based on existing dealer_setup -- then go from there ig




    # coalition group setup
    coalition_groups = generate_coalitions(params, party_ids)
    sharding_state = assign_keys_to_all_coalitions(params, coalition_groups) 









    return [dealer_setup_output, sharding_state]    


def coalition_signature_scheme(
    message: bytes,
    key_id: int,
    coalition: CoalitionGroup,
    # party_bundles: Dict[str, PartyBundle],        # we changed it to trusteeShare now
    dealer_output: DealerOutput,
    params: SystemParameters,
    coalition_groups: List[CoalitionGroup]  #? 
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

    # select coalition group and key
    selected_group, selected_key = select_signing_coalition_and_key(coalition_groups)




    pass