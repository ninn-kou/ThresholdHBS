import ctypes
import os
from ctypes import Structure, POINTER, c_ubyte, c_int64
from math import ceil, log2
from typing import List, Tuple

_lib = ctypes.CDLL(os.path.join('./', "winternitz.dll"), winmode=0)

class WinternitzKeyPair(Structure):
    _fields_ = [
        ("privateKey", POINTER(c_ubyte)),
        ("publicKey", POINTER(c_ubyte)),
    ]


_lib.NimMain.argtypes = []
_lib.NimMain.restype = None
_lib.NimMain()

_lib.generate_keypair.argtypes = [c_int64, c_int64]
_lib.generate_keypair.restype = WinternitzKeyPair


def generate_keypair(n: int, w: int) -> Tuple[List[List[bytes]], List[bytes]]:
    result = _lib.generate_keypair(n, w)

    a = n // w
    pow_w = 1 << w
    c = int(ceil(log2(a * (pow_w - 1)) / w))
    block_size = n // 8

    # Private key: (a + c) rows x pow_w columns, already row-major in the buffer.
    private_key: List[List[bytes]] = []
    offset = 0
    for _ in range(a + c):
        row: List[bytes] = []
        for _ in range(pow_w):
            row.append(bytes(result.privateKey[offset:offset + block_size]))
            offset += block_size
        private_key.append(row)

    # Public key: (a + c) elements, each block_size bytes.
    public_key: List[bytes] = []
    offset = 0
    for _ in range(a + c):
        public_key.append(bytes(result.publicKey[offset:offset + block_size]))
        offset += block_size

    return private_key, public_key

if __name__ == "__main__":
    n = 256
    w = 4
    private_key, public_key = generate_keypair(n, w)
    print("Private Key:")
    for row in private_key:
        print([elem for elem in row])
    print("\nPublic Key:")
    for elem in public_key:
        print(elem)