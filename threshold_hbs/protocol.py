from __future__ import annotations

import functools
import os
import secrets
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .lamport import hash_message, lamport_generate_keypair, lamport_sign, lamport_verify
from .merkle import MerkleTree, build_merkle_tree, get_auth_path, verify_merkle_path
from .models import (
    CommonReferenceValue,
    DealerOutput,
    SystemParameters,
    ThresholdSignature,
    TrusteeShare,
    TrusteeSharePerKey,
)
from .sharing import (
    estimate_crv_size_bytes,
    estimate_signature_size_bytes,
    key_id_to_bytes,
    lamport_public_key_from_secret_key,
    prf_hmac,
    signing_digest_bytes,
    xor,
    xor_byte_lists,
    xor_lamport_keys,
    xor_many_bytes,
)


class SigningRefusedError(RuntimeError):
    pass


class KeyReuseError(SigningRefusedError):
    pass


# This only handles the K-of-K case so far, I need to refactor this to allow for multiple parties of varying sizes from 2...k
# The module layout now separates primitives from protocol logic, but the public function names are intentionally kept.
def dealer_setup(params: SystemParameters, party_ids: Sequence[str]) -> DealerOutput:
    if party_ids and len(party_ids) != params.num_parties:
        raise ValueError("len(party_ids) must equal params.num_parties when party_ids is provided")

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
    trustees_shares: List[List[TrusteeSharePerKey | None]] = [[None] * params.num_leaves for _ in range(params.num_parties)]

    merkle_tree, composite_public_key = build_merkle_tree(public_keys, params.hash_name)

    prf_keys: List[bytes] = [secrets.token_bytes(32) for _ in range(params.num_parties)]

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

        for index, prf_key in enumerate(prf_keys):
            chk.append(prf_hmac(prf_key, "AUTH", key_id_bytes + randomizer, params.digest_size_bytes))
            randomizer_shares.append(prf_hmac(prf_key, "R", key_id_bytes, params.digest_size_bytes))

            chk_share_raw = prf_hmac(prf_key, "CHK", key_id_bytes, params.digest_size_bytes * len(prf_keys))
            chk_split = []

            for i in range(len(prf_keys)):
                chk_split.append(chk_share_raw[(i * params.digest_size_bytes):((i + 1) * params.digest_size_bytes)])

            chk_shares.append(chk_split)

            # Computing the path shares
            ps_raw = prf_hmac(prf_key, "PATH", key_id_bytes, sum(map(lambda x: len(x), path)))
            ps_split = []

            i, j = 0, 0
            while i < len(ps_raw):
                l = len(path[j])
                ps_split.append(ps_raw[i:i + l])
                j += 1
                i += l

            path_shares.append(ps_split)

            # every row of the secret_key should be the same hence the length of secret_key[0] is sufficient
            secret_key_shares.append([])
            public_key_shares.append([])
            for i in range(len(secret_key)):
                secret_key_shares[index].append([])
                public_key_shares[index].append([])
                for j in range(len(secret_key[0])):
                    secret_key_shares[index][i].append(
                        prf_hmac(
                            prf_key,
                            "CHAIN",
                            key_id_bytes + i.to_bytes(4, "big") + j.to_bytes(2, "big"),
                            params.lamport_element_size_bytes,
                        )
                    )
                    public_key_shares[index][i].append(
                        prf_hmac(
                            prf_key,
                            "PUBLIC",
                            key_id_bytes + i.to_bytes(4, "big") + j.to_bytes(2, "big"),
                            len(public_key[i][j]),
                        )
                    )

            randomizer_share = randomizer_shares[-1]
            randomizer_checker_share = chk_shares[-1]
            path_share = path_shares[-1]
            sk_share = secret_key_shares[-1]
            pk_share = public_key_shares[-1]

            trustees_shares[index][key_id] = TrusteeSharePerKey(
                randomizer_share=randomizer_share,
                randomizer_checker_share=randomizer_checker_share,
                path_share=path_share,
                sk_share=sk_share,
                pk_share=pk_share,
            )

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
            path=functools.reduce(lambda x, y: list(map(lambda z: xor(z[0], z[1]), zip(x, y))), path_shares, path),
            randomizer_checker=functools.reduce(lambda x, y: list(map(lambda z: xor(z[0], z[1]), zip(x, y))), chk_shares, chk),
            secret_key=crv_secret_key,
            public_key=crv_public_key,
        )

        common_reference_values[key_id] = crv

    trustees = []

    for prf_key, shares in zip(prf_keys, trustees_shares):
        trustees.append(TrusteeShare(
            prf_key=prf_key,
            shares=shares,
            hash_name=params.hash_name,
        ))

    return DealerOutput(
        party_id="",
        composite_public_key=composite_public_key,
        common_reference_values=common_reference_values,  # type: ignore[arg-type]
        members={i: trustee for i, trustee in enumerate(trustees)},
        public_keys_by_key_id=public_keys,
    )


def sign_1(share: TrusteeShare, key_id: int, message: bytes) -> Tuple[bytes, List[bytes]]:
    # These are supposed to be compute in real time but, I am caching them because I just am...
    if key_id in share.used_keys:
        raise KeyReuseError(f"key_id {key_id} has already been used by this trustee")
    if share.current is not None:
        raise SigningRefusedError("trustee already has a pending signing request")

    share.used_keys.add(key_id)
    share.current = (key_id, message)
    return (share.shares[key_id].randomizer_share, share.shares[key_id].randomizer_checker_share)


def auth_sign(share: TrusteeShare, key_id: int, randomizer: bytes, randomizer_checker: bytes) -> bool:
    return prf_hmac(share.prf_key, "AUTH", key_id_to_bytes(key_id) + randomizer, len(randomizer_checker)) == randomizer_checker


def sign_2(share: TrusteeShare, key_id: int, message: bytes, randomizer: bytes, randomizer_checker: bytes) -> Tuple[List[bytes], List[bytes]]:
    if share.current is None:
        raise SigningRefusedError("trustee has no pending signing request")

    current_key_id, current_message = share.current
    share.current = None

    if current_key_id != key_id or current_message != message:
        raise SigningRefusedError("mismatched second-round request")

    if auth_sign(share, key_id, randomizer, randomizer_checker):
        digest_size_bytes = len(share.shares[key_id].sk_share) // 8
        h = signing_digest_bytes(message, key_id, randomizer, digest_size_bytes, share.hash_name)
        return (share.shares[key_id].path_share, lamport_sign(h, share.shares[key_id].sk_share))
    else:
        raise SigningRefusedError("trustee refused to sign because the randomizer check failed")


def party_sign_share(
    party_bundle: DealerOutput,
    message: bytes,
    key_id: int,
    params: SystemParameters,
) -> Optional[Tuple[bytes, List[bytes], List[bytes]]]:
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

    if key_id in party_bundle.used_keys:
        raise KeyReuseError(f"key_id {key_id} has already been used by this party bundle")
    party_bundle.used_keys.add(key_id)

    randomizer = party_bundle.common_reference_values[key_id].randomizer
    chk = list(party_bundle.common_reference_values[key_id].randomizer_checker)

    for _, trustee_share in party_bundle.members.items():
        (r_share, chk_share) = sign_1(trustee_share, key_id, message)
        randomizer = xor(randomizer, r_share)
        chk = list(map(lambda z: xor(z[0], z[1]), zip(chk, chk_share)))

    h = signing_digest_bytes(message, key_id, randomizer, params.digest_size_bytes, params.hash_name)
    z = lamport_sign(h, party_bundle.common_reference_values[key_id].secret_key)
    path = list(party_bundle.common_reference_values[key_id].path)

    for i, trustee_share in party_bundle.members.items():
        (path_share, z_share) = sign_2(trustee_share, key_id, message, randomizer, chk[i])
        z = list(map(lambda x: xor(x[0], x[1]), zip(z, z_share)))
        path = list(map(lambda x: xor(x[0], x[1]), zip(path, path_share)))

    return (randomizer, path, z)


def _reconstruct_lamport_public_key(party_bundle: DealerOutput, key_id: int) -> List[List[bytes]]:
    lamport_public_key = [[bytes(value) for value in pair] for pair in party_bundle.common_reference_values[key_id].public_key]
    for trustee_share in party_bundle.members.values():
        lamport_public_key = [
            [xor(lamport_public_key[i][j], trustee_share.shares[key_id].pk_share[i][j]) for j in range(len(lamport_public_key[i]))]
            for i in range(len(lamport_public_key))
        ]
    return lamport_public_key


def aggregator_sign(
    message: bytes,
    key_id: int,
    party_bundles: Sequence[Any] | DealerOutput,
    auth_path: Optional[Sequence[bytes]] = None,
    params: Optional[SystemParameters] = None,
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

    result = party_sign_share(party_bundle, message, key_id, params)
    if result is None:
        raise SigningRefusedError("party_sign_share returned None")
    (randomizer, path, z) = result

    if auth_path is not None and list(auth_path) != list(path):
        raise ValueError("provided auth_path does not match the reconstructed path")

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
    digest = signing_digest_bytes(message, signature.key_id, signature.randomizer, params.digest_size_bytes, params.hash_name)

    lamport_ok = lamport_verify(
        digest,
        signature.lamport_signature_values,
        signature.lamport_public_key,
        params.hash_name,
    )
    if not lamport_ok:
        return False

    return verify_merkle_path(
        signature.lamport_public_key,
        signature.key_id,
        signature.auth_path,
        root_public_key,
        params.hash_name,
    )


def benchmark_minimal_prototype(
    params: SystemParameters,
    messages: Sequence[bytes],
    dealer_output: Any,
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
    if len(messages) > params.num_leaves:
        raise ValueError("Need at least as many leaves as messages to benchmark")

    sign_start = time.perf_counter()
    signatures = [
        aggregator_sign(message, key_id, dealer_output, None, params)
        for key_id, message in enumerate(messages)
    ]
    sign_total_s = time.perf_counter() - sign_start

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
