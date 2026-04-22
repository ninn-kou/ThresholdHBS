from __future__ import annotations

import hashlib
import secrets
from ..abstractions import SignatureScheme
from typing import Any, List, Sequence, Tuple

class LamportSignatureScheme(SignatureScheme):

    def __init__(self, digest_size, element_size, hash_name = "sha256"):
        super().__init__(digest_size, element_size, hash_name)

    def generate_keypair(self):
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
        num_bits = self.digest_size * 8
        secret_key: List[List[bytes]] = []
        public_key: List[List[bytes]] = []

        for _ in range(num_bits):
            sk0 = secrets.token_bytes(self.element_size)
            sk1 = secrets.token_bytes(self.element_size)
            pk0 = self.hash_message(sk0)
            pk1 = self.hash_message(sk1)
            secret_key.append([sk0, sk1])
            public_key.append([pk0, pk1])

        return secret_key, public_key
    
    def sign(self, message, secret_key):
        """Produce a Lamport signature for one digest.

        Args:
            message: Message digest produced by ``hash_message``.
            secret_key: Full Lamport secret key for a single leaf.

        Returns:
            The list of Lamport values revealed for this digest.

        Purpose:
            Selects one secret element per digest bit to form the one-time signature.
        """
        signature_values: List[bytes] = []
        for byte_index, byte_val in enumerate(message):
            for bit_position in range(7, -1, -1):
                bit = (byte_val >> bit_position) & 1
                i = byte_index * 8 + (7 - bit_position)
                signature_values.append(secret_key[i][bit])
        return signature_values
    
    def verify(self, message, signature, public_key) -> bool:
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
        num_bits = len(message) * 8
        if len(signature) != num_bits:
            return False

        for byte_index, byte_val in enumerate(message):
            for bit_position in range(7, -1, -1):
                bit = (byte_val >> bit_position) & 1
                i = byte_index * 8 + (7 - bit_position)
                revealed = signature[i]
                expected_pk = public_key[i][bit]
                if self.hash_message(revealed) != expected_pk:
                    return False
        return True


def lamport_generate_keypair(digest_size, element_size, hash_name="sha256"):
    scheme = LamportSignatureScheme(digest_size, element_size, hash_name)
    return scheme.generate_keypair()


def lamport_sign(message, secret_key, hash_name="sha256"):
    scheme = LamportSignatureScheme(len(message), 0, hash_name)
    return scheme.sign(message, secret_key)
