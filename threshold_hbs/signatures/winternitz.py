from __future__ import annotations
from typing import List, Tuple
from ..abstractions import SignatureScheme
from ..winternitz.helpers import (
    generate_keypair as _nim_generate_keypair,
    sign as _nim_sign,
    verify as _nim_verify,
)
from math import ceil, log2


class WinternitzSignatureScheme(SignatureScheme):
    def __init__(self, digest_size: int, element_size: int, w: int, hash_name: str = "sha256") -> None:
        super().__init__(digest_size, element_size, hash_name)

        # element_size is in bytes; Nim code expects n in bits
        self.n = self.element_size * 8

        # ensure n is divisible by w as required for Winternitz splitting
        if self.n % w != 0:
            raise ValueError("element_size * 8 must be an integer multiple of w")
        
        self.w = w
        # number of chunks when splitting the message into w-bit pieces
        self.a = self.n // self.w
        # number of extra checksum chunks to ensure integrity
        self.c = int(ceil(log2(self.a * (2**self.w - 1)) / self.w))

    def generate_keypair(self) -> Tuple[List[List[bytes]], List[List[bytes]]]:
        private_key, public_key = _nim_generate_keypair(self.n, self.w)
        # Wrap public key elements to match List[List[bytes]] interface
        wrapped_pk = [[elem] for elem in public_key]
        return private_key, wrapped_pk

    def sign(self, message: bytes, secret_key: List[List[bytes]]) -> List[bytes]:
        return _nim_sign(message, secret_key, self.n, self.w)

    def verify(self, message: bytes, signature: List[bytes], public_key: List[List[bytes]]) -> bool:
        # Unwrap public key from List[List[bytes]] back to List[bytes]
        unwrapped_pk = [elem[0] for elem in public_key]
        return _nim_verify(message, signature, unwrapped_pk, self.n, self.w)
