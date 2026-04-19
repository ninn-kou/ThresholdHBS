"""Extension 1: k-of-n via k-of-k subtrees / sharding.

Recommended responsibilities:
- coalition list (CL) representation
- KeyID allocation per coalition
- coalition-aware signing coordinator
"""

from typing import Iterable, List, Sequence, Dict
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
    dealer_setup
)

from ..lamport import (
    lamport_generate_keypair
)

from ..merkle import (
    build_merkle_tree,
    get_auth_path
)

from ..sharing import (
    key_id_to_bytes,
    prf_hmac,
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
        # party_id="",    
        composite_public_key=composite_public_key,
        common_reference_values=common_reference_values,  # type: ignore[arg-type]
        members={trustee.party_id: trustee for trustee in trustees},
        public_keys_by_key_id=public_keys,
    )

    return (dealer_output, sharding_state)   

    # refractor this pls its so long omg




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