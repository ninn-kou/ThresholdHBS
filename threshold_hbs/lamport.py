from __future__ import annotations

import hashlib
import secrets
from typing import Any, List, Sequence, Tuple


def hash_message(message: bytes, hash_name: str = "sha256") -> bytes:
    """Hash a message for Lamport signing.

    Args:
        message: Raw message bytes to be signed.
        hash_name: Name of the hash algorithm to use.

    Returns:
        Digest bytes that will be interpreted bit-by-bit by Lamport signing.

    Purpose:
        Converts an arbitrary-length message into the fixed-length digest used by
        Lamport sign and verify operations.
    """
    h = hashlib.new(hash_name)
    h.update(message)
    return h.digest()


def lamport_generate_keypair(
    digest_size_bytes: int,
    element_size_bytes: int,
    hash_name: str = "sha256",
) -> Tuple[List[List[bytes]], List[List[bytes]]]:
    """Generate one Lamport one-time keypair.

    Args:
        digest_size_bytes: Digest length that determines the number of Lamport positions.
        element_size_bytes: Byte length of each secret element.
        hash_name: Name of the hash algorithm used to derive the public key.

    Returns:
        A tuple ``(secret_key, public_key)`` for one Lamport leaf.

    Purpose:
        Creates the one-time signing material stored at one Merkle-tree leaf.
    """
    num_bits = digest_size_bytes * 8
    secret_key: List[List[bytes]] = []
    public_key: List[List[bytes]] = []

    for _ in range(num_bits):
        sk0 = secrets.token_bytes(element_size_bytes)
        sk1 = secrets.token_bytes(element_size_bytes)
        pk0 = hash_message(sk0, hash_name)
        pk1 = hash_message(sk1, hash_name)
        secret_key.append([sk0, sk1])
        public_key.append([pk0, pk1])

    return secret_key, public_key



def lamport_sign(digest: bytes, secret_key: Any) -> List[bytes]:
    """Produce a Lamport signature for one digest.

    Args:
        digest: Message digest produced by ``hash_message``.
        secret_key: Full Lamport secret key for a single leaf.

    Returns:
        The list of Lamport values revealed for this digest.

    Purpose:
        Selects one secret element per digest bit to form the one-time signature.
    """
    signature_values: List[bytes] = []
    for byte_index, byte_val in enumerate(digest):
        for bit_position in range(7, -1, -1):
            bit = (byte_val >> bit_position) & 1
            i = byte_index * 8 + (7 - bit_position)
            signature_values.append(secret_key[i][bit])
    return signature_values



def lamport_verify(
    digest: bytes,
    signature_values: Sequence[bytes],
    public_key: Any,
    hash_name: str = "sha256",
) -> bool:
    """Verify a Lamport one-time signature.

    Args:
        digest: Message digest produced by ``hash_message``.
        signature_values: Revealed Lamport values from the signature.
        public_key: Lamport public key for the leaf being verified.
        hash_name: Name of the hash algorithm used in the Lamport construction.

    Returns:
        ``True`` if the Lamport signature is valid, else ``False``.

    Purpose:
        Checks the one-time signature independently of the Merkle tree.
    """
    num_bits = len(digest) * 8
    if len(signature_values) != num_bits:
        return False

    for byte_index, byte_val in enumerate(digest):
        for bit_position in range(7, -1, -1):
            bit = (byte_val >> bit_position) & 1
            i = byte_index * 8 + (7 - bit_position)
            revealed = signature_values[i]
            expected_pk = public_key[i][bit]
            if hash_message(revealed, hash_name) != expected_pk:
                return False
    return True
