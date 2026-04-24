from __future__ import annotations

import hashlib
from typing import List, Tuple
from abc import ABC, abstractmethod

class SignatureScheme (ABC):
    """Abstract interface for signature schemes."""
    def __init__ (self, digest_size: int, element_size: int, hash_name: str = "sha256") -> None:
        self.digest_size = digest_size
        self.element_size = element_size
        self.hash_name = hash_name

    def hash_message (self, message: bytes) -> bytes:
        h = hashlib.new(self.hash_name)
        h.update(message)
        return h.digest()
    
    @abstractmethod
    def generate_keypair (self) -> Tuple[List[List[bytes]], List[List[bytes]]]:
        pass

    @abstractmethod
    def sign (self, message: bytes, secret_key: List[List[bytes]]) -> List[bytes]:
        pass

    @abstractmethod
    def verify (self, message: bytes, signature: List[bytes], public_key: List[List[bytes]]) -> bool:
        pass