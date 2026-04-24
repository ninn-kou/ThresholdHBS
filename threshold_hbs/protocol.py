from __future__ import annotations
from itertools import combinations
from typing import Any, Dict, List, Optional, Sequence, Tuple
from threshold_hbs.exceptions import KeyReuseError, SigningRefusedError

import functools
import hashlib
import os
import secrets
import time

from .merkle import MerkleTree, build_merkle_tree_messages, build_merkle_tree_signatures, get_auth_path, verify_merkle_path
from .models import (
    BatchSignature,
    CoalitionGroup,
    CommonReferenceValue,
    DealerOutput,
    ShardingState,
    SystemParameters,
    ThresholdSignature,
    TrusteeShare,
    TrusteeSharePerKey,
)
from .sharing import (
    estimate_crv_size_bytes,
    estimate_signature_size_bytes,
    key_id_to_bytes,
    prf_hmac,
    signing_digest_bytes,
    xor
)

# constants
PRF_LABEL_AUTH = "AUTH"
PRF_LABEL_RANDOMIZER = "R"
PRF_LABEL_CHECKER = "CHK"
PRF_LABEL_PATH = "PATH"
PRF_LABEL_CHAIN = "CHAIN"
PRF_LABEL_PUBLIC = "PUBLIC"

def dealer_setup(      
    params: SystemParameters,
    party_ids: Sequence[str]
) -> tuple[DealerOutput, ShardingState]: 
    """
    Performs Extension 1 setup using a PRF-based threshold HBS scheme.

    Generates Lamport keys and Merkle tree, assigns key_ids to coalition groups,
    derives per-party shares using PRFs, and constructs CRVs.

    Returns DealerOutput and ShardingState.
    """

    # sanity check 
    if party_ids and len(party_ids) != params.num_parties:
        raise ValueError("len(party_ids) must equal params.num_parties when party_ids is provided")
    
    # coalition group setup
    coalition_groups = generate_coalitions(params, party_ids)
    sharding_state = assign_keys_to_all_coalitions(params, coalition_groups) 

    # generate Lamport keys and corresponding public keys
    secret_keys = []
    public_keys = []

    scheme = params.signature_scheme

    for key_id in range(params.num_leaves):
        secret_key, public_key = scheme.generate_keypair()

        secret_keys.append(secret_key)
        public_keys.append(public_key)

    common_reference_values: List[CommonReferenceValue | None] = [None] * params.num_leaves

    merkle_tree, composite_public_key = build_merkle_tree_signatures(public_keys, params.hash_name)

    # distribute prf key to parties
    prf_keys: List[bytes] = [secrets.token_bytes(params.digest_size_bytes) for _ in range(params.num_parties)]

    # create all parties
    trustees = [] 

    for index, party in enumerate(party_ids): 
        trustees.append(TrusteeShare(
            prf_key=prf_keys[index],
            shares=[],
            party_id=party,
            hash_name=params.hash_name
        ))
    
     # compute the shares and common reference value
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

            # retrieve trustee object for this coalition member
            trustee = next((t for t in trustees if t.party_id == member), None)
            
            if trustee is None:
                raise ValueError(f"Trustee not found for party_id {member}")
            
            prf_seed = trustee.prf_key
            # derive authentication value using PRF
            chk.append(prf_hmac(prf_seed, PRF_LABEL_AUTH, key_id_bytes + randomizer, params.digest_size_bytes))
            # derive randomizer share for this party
            randomizer_shares.append(prf_hmac(prf_seed, PRF_LABEL_RANDOMIZER, key_id_bytes, params.digest_size_bytes))

            coalition_size = len(assigned_coalition_group)
            
            # expand PRF output and split into per-member checker shares
            chk_share_raw = prf_hmac(prf_seed, PRF_LABEL_CHECKER, key_id_bytes, params.digest_size_bytes * coalition_size)
            chk_split = []

            for i in range(coalition_size):
                chk_split.append(chk_share_raw[(i * params.digest_size_bytes):((i + 1) * params.digest_size_bytes)])

            chk_shares.append(chk_split)

            # derive shares for each Merkle authentication path node
            ps_raw = prf_hmac(prf_seed, PRF_LABEL_PATH, key_id_bytes, sum(map(lambda x: len(x), path)))
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
                            PRF_LABEL_CHAIN,
                            key_id_bytes + i.to_bytes(4, "big") + j.to_bytes(2, "big"),
                            params.lamport_element_size_bytes,
                        ))

                for j in range(len(public_key[0])):
                    member_public_key_share[i].append(prf_hmac(
                            prf_seed,
                            PRF_LABEL_PUBLIC,
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

            # save it to trusteeperkey
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
            for j in range(len(public_key[0])):
                for public_key_share in public_key_shares:
                    crv_public_key[i][j] = xor(crv_public_key[i][j], public_key_share[i][j])

        # combine all shares to form final CRV for this key_id
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

# First round of signing: returns this trustee's randomizer share and checker share
def sign_1(share: TrusteeShare, key_id: int, message: bytes) -> Tuple[bytes, List[bytes]]:
    # sanity check 
    if key_id in share.used_keys:
        raise KeyReuseError(f"key_id {key_id} has already been used by this trustee")
    if share.current is not None:
        raise SigningRefusedError("trustee already has a pending signing request")

    share.used_keys.add(key_id)
    share.current = (key_id, message)

    # find trustee's share on the given key_id
    trustee_share = None
    for term in share.shares:
        if term.key_id == key_id:
            trustee_share = term
            break
    
    if trustee_share is None: 
        raise SigningRefusedError(f"Trustee has no share for key_id {key_id}")
    
    return (trustee_share.randomizer_share, trustee_share.randomizer_checker_share)

# Verifies that the reconstructed randomizer is valid using PRF-based authentication
def auth_sign(share: TrusteeShare, key_id: int, randomizer: bytes, randomizer_checker: bytes) -> bool:
    return prf_hmac(share.prf_key, PRF_LABEL_AUTH, key_id_to_bytes(key_id) + randomizer, len(randomizer_checker)) == randomizer_checker

# Second round of signing: returns this trustee's Merkle path share and Lamport signature share
def sign_2(share: TrusteeShare, key_id: int, message: bytes, randomizer: bytes, randomizer_checker: bytes, params: SystemParameters = None) -> Tuple[List[bytes], List[bytes]]:
    if share.current is None:
        raise SigningRefusedError("trustee has no pending signing request")

    current_key_id, current_message = share.current
    share.current = None

    if current_key_id != key_id or current_message != message:
        raise SigningRefusedError("mismatched second-round request")

    # verifies correctness
    if auth_sign(share, key_id, randomizer, randomizer_checker):
        # find trustee's share on the given key_id
        trustee_share = None
        for term in share.shares:
            if term.key_id == key_id:
                trustee_share = term
                break

        if trustee_share is None: 
            raise SigningRefusedError(f"Trustee has no share for key_id {key_id}")

        # compute path share and signature share
        digest_size_bytes = params.digest_size_bytes if params else len(trustee_share.sk_share) // 8
        h = signing_digest_bytes(message, key_id, randomizer, digest_size_bytes, share.hash_name)
        return (trustee_share.path_share, params.signature_scheme.sign(h, trustee_share.sk_share))
    else:
        raise SigningRefusedError("trustee refused to sign because the randomizer check failed")

# Coordinates threshold signing across all trustees to produce a full signature
def party_sign_share(
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

    for trustee_share in party_bundle.members.values():
        (r_share, chk_share) = sign_1(trustee_share, key_id, message)
        # reconstruct randomizer and checker by XOR-ing all trustee shares
        randomizer = xor(randomizer, r_share)
        chk = list(map(lambda z: xor(z[0], z[1]), zip(chk, chk_share)))

    # compute digest and initial Lamport signature using dealer-held CRV
    h = signing_digest_bytes(message, key_id, randomizer, params.digest_size_bytes, params.hash_name)
    z = params.signature_scheme.sign(h, party_bundle.common_reference_values[key_id].secret_key)
    path = list(party_bundle.common_reference_values[key_id].path)

    for i, trustee_share in enumerate(party_bundle.members.values()):
        # collect second-round shares and reconstruct final signature and path
        (path_share, z_share) = sign_2(trustee_share, key_id, message, randomizer, chk[i], params)
        z = list(map(lambda x: xor(x[0], x[1]), zip(z, z_share)))
        path = list(map(lambda x: xor(x[0], x[1]), zip(path, path_share)))

    return (randomizer, path, z)

# Reconstructs Lamport public key by XOR-ing CRV value with all trustee shares
def _reconstruct_lamport_public_key(party_bundle: DealerOutput, key_id: int) -> List[List[bytes]]:
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

# Aggregates trustee signing shares into a final threshold signature
# Reconstructs the randomizer, Merkle path, Lamport signature, and public key
def aggregator_sign(
    message: bytes,
    key_id: int,
    party_bundles: Sequence[Any] | DealerOutput,
    auth_path: Optional[Sequence[bytes]] = None,
    params: Optional[SystemParameters] = None,
) -> ThresholdSignature:

    if params is None:
        raise ValueError("params is required")

    # implementation expects a single DealerOutput
    if isinstance(party_bundles, DealerOutput):
        party_bundle = party_bundles
    elif len(party_bundles) == 1 and isinstance(party_bundles[0], DealerOutput):
        party_bundle = party_bundles[0]
    else:
        raise TypeError(
            "party_bundles must be a DealerOutput or a length-1 sequence containing one."
        )

    # threshold signing across all trustees to reconstruct randomizer, path, and lamport signature values
    result = party_sign_share(party_bundle, message, key_id, params)
    if result is None:
        raise SigningRefusedError("party_sign_share returned None")
    (randomizer, path, z) = result

    # ensures the provided path matches reconstructed path
    if auth_path is not None and list(auth_path) != list(path):
        raise ValueError("provided auth_path does not match the reconstructed path")

    # reconstruct lamport public key by combining CRV with trustee shares
    lamport_public_key = _reconstruct_lamport_public_key(party_bundle, key_id)

    return ThresholdSignature(
        key_id=key_id,
        randomizer=randomizer,
        lamport_public_key=lamport_public_key,
        lamport_signature_values=z,
        auth_path=path,
    )


def verify_threshold_signature(
    message: bytes,
    signature: ThresholdSignature,
    root_public_key: bytes,
    params: SystemParameters,
) -> bool:
    """
    Verifies a threshold signature.

    Checks both the Lamport signature over the message digest
    and the Merkle path to the root public key.
    """

    # compute message digest using key_id and randomizer 
    digest = signing_digest_bytes(
        message, 
        signature.key_id, 
        signature.randomizer, 
        params.digest_size_bytes, 
        params.hash_name
    )

    # verigy lamport signaure
    lamport_ok = params.signature_scheme.verify(
        digest,
        signature.lamport_signature_values,
        signature.lamport_public_key,
    )
    if not lamport_ok:
        return False

    # verify that the lamport public key is part of the merkle tree
    return verify_merkle_path(
        signature.lamport_public_key,
        signature.key_id,
        signature.auth_path,
        root_public_key,
        params.hash_name,
    )


def benchmark(
    params: SystemParameters,
    messages: Sequence[bytes],
    dealer_output: DealerOutput,
    sharding_state: ShardingState
) -> Dict[str, float]:
    
    """
    Benchmarks coalition signing and verification performance.

    Returns timing results, average signature size, CRV storage size,
    and the number of successfully verified signatures.
    """
    
    if len(messages) > params.num_leaves:
        raise ValueError("Need at least as many leaves as messages to benchmark")

    sign_start = time.perf_counter()
    signatures = [
        # generate signatures using the coalition-based signing scheme
        coalition_signature_scheme(message, dealer_output, params, sharding_state)
        for message in enumerate(messages)
    ]
    sign_total_s = time.perf_counter() - sign_start
    
    # verify each generated signature against the Merkle root public key
    verify_start = time.perf_counter()
    verified = 0
    for message, signature in zip(messages, signatures):
        if verify_threshold_signature(message, signature, dealer_output.composite_public_key, params):
            verified += 1
    verify_total_s = time.perf_counter() - verify_start

    # compute average signature size across all generated signatures
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
    
# Generate every possible coalition 
def generate_coalitions(    
    params: SystemParameters,
    party_ids: Sequence[str]
) -> List[CoalitionGroup]:  
    
    # sanity checks - ensure the provided parties match the system configuration
    if party_ids and len(party_ids) != params.num_parties:
        raise ValueError("len(party_ids) must equal params.num_parties when party_ids is provided")
    # threshold_k defines how many parties are required in each coalition
    if params.threshold_k > len(party_ids):
        raise ValueError("Threshold value cannot be larger than existing number of parties")

    coalition_groups = []
    threshold_k = params.threshold_k

    # generate every possible coalition of size threshold_k
    for combination in combinations(party_ids, threshold_k):
        new_coalition = CoalitionGroup(
            group_members=combination,
            assigned_key_ids=[]   # key_ids are assigned later by assign_keys_to_all_coalitions()
        )

        coalition_groups.append(new_coalition)

    return coalition_groups

#  Assigns each key_id to one coalition group and builds the sharding state.
def assign_keys_to_all_coalitions(
    params: SystemParameters,
    coalition_groups: List[CoalitionGroup]
) -> ShardingState:

    key_num = params.num_leaves 
    # map each coalition's member tuple to its CoalitionGroup object
    coalition_to_keys = {group.group_members: group for group in coalition_groups}
    # map each key_id to the coalition responsible for signing with it
    key_to_coalition = {}

    for key_id in range(key_num):
        # sssign key_ids evenly across coalition groups using modulo
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

# Selects the first coalition with an unused assigned key_id
def select_signing_coalition_and_key(
    coalition_groups: List[CoalitionGroup]
) -> tuple[CoalitionGroup, int]: 
    
    # search coalitions in order for an unused assigned key_id
    for group in coalition_groups:
        for key in group.assigned_key_ids:
            # find unused key
            if key not in group.used_key_ids: 
                # reserve the key_id so it cannot be reused for another signature
                group.used_key_ids.add(key)
                return (group, key)

    raise ValueError("No available coalition/key pair remains")


def batch_coalition_signature_scheme(
    messages: List[bytes],
    dealer_output: DealerOutput,
    params: SystemParameters,
    sharding_state: ShardingState
) -> List[BatchSignature]:
    
    """
    Extension 3: Buffers messages into a Merkle tree, signs the root via the 
    threshold scheme, and returns a BatchSignature for each message.
    """

    if not messages:
        raise ValueError("Must provide at least one message to batch sign.")
    # build a Merkle tree over all messages to enable batch signing
    message_tree, message_root = build_merkle_tree_messages(messages, params.hash_name)

    # sign the message-tree root once instead of signing every message separately
    root_threshold_signature = coalition_signature_scheme(
        message_root, dealer_output, params, sharding_state
    )

    batch_signatures = []
    for i in range(len(messages)):
        # store each message's authentication path for later verification
        path = get_auth_path(message_tree, i)
        batch_signatures.append(BatchSignature(
            message_index=i,
            message_auth_path=path,
            threshold_signature=root_threshold_signature
        ))
        
    return batch_signatures

def verify_batch_signature(
    message: bytes,
    batch_signatures: BatchSignature,
    root_public_key: bytes,
    params: SystemParameters
) -> bool:
    
    """
    Verifies a batch signature by reconstructing the message-tree root
    from the authentication path and verifying the threshold signature on that root.
    """

    current_digest = hashlib.new(params.hash_name, message).digest()
    pk_id = batch_signatures.message_index
    
    # reconstruct the Merkle root using the authentication path
    for sibling in batch_signatures.message_auth_path:
        if pk_id % 2 == 0:
            current_digest = MerkleTree.hash_digests(params.hash_name, current_digest, sibling)
        else:
            current_digest = MerkleTree.hash_digests(params.hash_name, sibling, current_digest)
        pk_id //= 2
        
    reconstructed_message_root = current_digest
    
    # verify that the reconstructed root was signed
    return verify_threshold_signature(
        message=reconstructed_message_root, 
        signature=batch_signatures.threshold_signature, 
        root_public_key=root_public_key, 
        params=params
    )


# wrapper for aggregator_sign
def coalition_signature_scheme(
    message: bytes,
    dealer_output: DealerOutput,
    params: SystemParameters,
    sharding_state: ShardingState
) -> ThresholdSignature:    

    """
    Signs a message using the coalition assigned to an unused key_id.

    Selects an available coalition/key pair, filters DealerOutput to that
    coalition's members, then delegates signing to aggregator_sign().
    """

    # get all coalition groups from the sharding state
    coalition_groups = list(sharding_state.coalition_map.values())

    # select an unused key_id and the coalition responsible for signing it
    selected_group, key_id = select_signing_coalition_and_key(coalition_groups)

    # filter existing dealer_output to only contain members from selected coalition group
    group_members = {}

    for name, trustee in dealer_output.members.items():
        if name in selected_group.group_members: 
            group_members[name] = trustee

    # create a temporary DealerOutput containing only the selected coalition members
    new_dealer_output = DealerOutput(
        party_id=dealer_output.party_id,  
        composite_public_key=dealer_output.composite_public_key,
        common_reference_values=dealer_output.common_reference_values,
        public_keys_by_key_id=dealer_output.public_keys_by_key_id,
        members=group_members,
        used_keys=dealer_output.used_keys
    )   
    # delegate the actual two-round signing and share reconstruction back to aggregator_sign
    threshold_signature = aggregator_sign(message, key_id, new_dealer_output, None, params)

    return threshold_signature

