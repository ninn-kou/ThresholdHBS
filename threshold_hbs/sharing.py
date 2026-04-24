from __future__ import annotations
from typing import List, Sequence
from .signatures.lamport import LamportSignatureScheme

import functools
import hashlib
import hmac

"""
Utility functions for the threshold hash-based signature scheme.
"""

# The digest_size and element_size parameters do not affects the functionality of hash_message
hash_message = LamportSignatureScheme(digest_size=32, element_size=32).hash_message

# PRF using HMAC-SHA256 with domain separation via lable
def prf_hmac(
    key: bytes,
    label: str,
    input: bytes,
    output_length: int,
) -> bytes:
    message = len(label).to_bytes(1, "big") + label.encode("utf-8") + input

    h = hmac.new(key, message, "sha256")
    digest = h.digest()

    if len(digest) > output_length:
        return digest[:output_length]
    else:
        return hashlib.pbkdf2_hmac("sha256", digest, b"", 1, dklen=output_length)


# Byte-wise XOR of two equal-length byte strings
def xor(a: bytes, b: bytes) -> bytes:
    return bytes([_a ^ _b for _a, _b in zip(a, b)])

# Concatenates a list of byte strings into one
def concat(x: List[bytes]) -> bytes:
    return functools.reduce(lambda a, b: a + b, x, b"")

# Converts key_id to the smallest number of bytes
def key_id_to_bytes(key_id: int) -> bytes:
    # convert key_id to minimal big-endian byte representation
    width = max(1, (int(key_id).bit_length() + 7) // 8)
    return int(key_id).to_bytes(width, "big")

# XORs multiple byte strings together
def xor_many_bytes(values: Sequence[bytes]) -> bytes:
    if not values:
        return b""
    result = values[0]
    for value in values[1:]:
        result = xor(result, value)
    return result

# Element-wise XOR across lists of byte strings
def xor_byte_lists(base: Sequence[bytes], shares: Sequence[Sequence[bytes]]) -> List[bytes]:
    result = [bytes(value) for value in base]
    for share in shares:
        result = [xor(left, right) for left, right in zip(result, share)]
    return result

# Element-wise XOR of Lamport key pairs
# Used to combine Lamport secret/public key shares
def xor_lamport_keys(base: Sequence[Sequence[bytes]], shares: Sequence[Sequence[Sequence[bytes]]]) -> List[List[bytes]]:
    result = [[bytes(value) for value in pair] for pair in base]
    for share in shares:
        result = [
            [xor(result[i][j], share[i][j]) for j in range(len(result[i]))]
            for i in range(len(result))
        ]
    return result

# Derives Lamport public key by hashing each secret key element
def lamport_public_key_from_secret_key(secret_key, hash_name: str = "sha256"):
    public_key = []
    for pair in secret_key:
        public_key.append([hash_message(pair[0], hash_name), hash_message(pair[1], hash_name)])
    return public_key

# Computes signing digest and ensures uniqueness per signature
def signing_digest_bytes(message: bytes, key_id: int, randomizer: bytes, digest_size_bytes: int, hash_name: str) -> bytes:
    # bind key_id and randomness to prevent reuse of one-time keys
    digest = hash_message(key_id_to_bytes(key_id) + randomizer + message)
    return digest[:digest_size_bytes]

# Estimates total signature size
def estimate_signature_size_bytes(signature) -> int:
    size = 0
    size += len(signature.randomizer)
    size += sum(len(value) for value in signature.lamport_signature_values)
    size += sum(len(node) for node in signature.auth_path)
    for pair in signature.lamport_public_key:
        for value in pair:
            size += len(value)
    size += max(1, (int(signature.key_id).bit_length() + 7) // 8)
    return size

# Computes total byte size of all common reference values (CRVs)
def estimate_crv_size_bytes(common_reference_values) -> int:
    size = 0
    for crv in common_reference_values:
        size += len(crv.randomizer)
        size += sum(len(value) for value in crv.randomizer_checker)
        size += sum(len(node) for node in crv.path)
        for pair in crv.secret_key:
            for value in pair:
                size += len(value)
        for pair in crv.public_key:
            for value in pair:
                size += len(value)
    return size
