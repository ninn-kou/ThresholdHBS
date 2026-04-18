"""Extension 5: Winternitz one-time signatures.

Recommended responsibilities:
- Winternitz key generation, sign, verify
- checksum and chain traversal helpers
- adapters so protocol.py can swap Lamport and Winternitz cleanly
"""

from __future__ import annotations
from ..abstractions import SignatureScheme

class WinternitzSignatureScheme(SignatureScheme):
    def __init__(self, w: int, n: int):
        self.w = w
        self.n = n 
