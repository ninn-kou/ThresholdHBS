"""Extension 5: Winternitz one-time signatures.

Recommended responsibilities:
- Winternitz key generation, sign, verify
- checksum and chain traversal helpers
- adapters so protocol.py can swap Lamport and Winternitz cleanly
"""

from __future__ import annotations
from typing import List
from ..abstractions import SignatureScheme
from math import ceil, log2

import secrets

class WinternitzSignatureScheme(SignatureScheme):
    def __init__(self, digest_size: int, element_size: int, w: int, hash_name: str = "sha256") -> None:
        super().__init__(digest_size, element_size, hash_name)

        if self.element_size % w != 0:
            raise ValueError("element_size must be an integer multiple of w")
        
        self.w = w
        self.a = self.element_size // self.w
        self.c = ceil(log2(self.a * (2**self.w - 1))/self.w)

    def generate_keypair(self):
        pass

    def sign (self, message: bytes, secret_key: List[List[bytes]]) -> List[bytes]:
        pass

    def verify(self, message: bytes, signature: List[bytes], public_key: List[List[bytes]]) -> bool:
        pass
