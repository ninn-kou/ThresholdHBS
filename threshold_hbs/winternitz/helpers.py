import ctypes
import os
import sys
from ctypes import Structure, POINTER, c_ubyte, c_int64
from math import ceil, log2
from typing import List, Tuple

_ext = ".dll" if sys.platform == "win32" else ".dylib" if sys.platform == "darwin" else ".so"
_path = os.path.join(os.path.dirname(__file__), "winternitz" + _ext)
_lib = ctypes.CDLL(_path, winmode=0) if sys.platform == "win32" else ctypes.CDLL(_path)

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

_lib.sign.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte), c_int64, c_int64]
_lib.sign.restype = POINTER(c_ubyte)

_lib.verify.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte), POINTER(c_ubyte), c_int64, c_int64]
_lib.verify.restype = ctypes.c_bool


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


def sign(message: bytes, secret_key: List[List[bytes]], n: int, w: int) -> List[bytes]:
    a = n // w
    pow_w = 1 << w
    c = int(ceil(log2(a * (pow_w - 1)) / w))
    block_size = n // 8

    # Flatten secret_key back into the raw layout: (a+c) chains, each pow_w * block_size bytes
    total_sk_bytes = (a + c) * pow_w * block_size
    sk_buf = (c_ubyte * total_sk_bytes)()
    offset = 0
    for chain in secret_key:
        for block in chain:
            for b in block:
                sk_buf[offset] = b
                offset += 1

    msg_buf = (c_ubyte * len(message))(*message)
    result = _lib.sign(msg_buf, sk_buf, n, w)

    signature: List[bytes] = []
    offset = 0
    for _ in range(a + c):
        signature.append(bytes(result[offset:offset + block_size]))
        offset += block_size

    return signature


def verify(message: bytes, signature: List[bytes], public_key: List[bytes], n: int, w: int) -> bool:
    a = n // w
    pow_w = 1 << w
    c = int(ceil(log2(a * (pow_w - 1)) / w))
    block_size = n // 8

    msg_buf = (c_ubyte * len(message))(*message)

    sig_flat = b''.join(signature)
    sig_buf = (c_ubyte * len(sig_flat))(*sig_flat)

    pk_flat = b''.join(public_key)
    pk_buf = (c_ubyte * len(pk_flat))(*pk_flat)

    return _lib.verify(msg_buf, sig_buf, pk_buf, n, w)


if __name__ == "__main__":
    n = 256
    w = 4
    private_key, public_key = generate_keypair(n, w)

    message = bytes(range(n // 8))
    sig = sign(message, private_key, n, w)
    assert verify(message, sig, public_key, n, w), "Verification failed for valid signature"

    tampered = bytes([message[0] ^ 1]) + message[1:]
    assert not verify(tampered, sig, public_key, n, w), "Verification passed for tampered message"

    print("All tests passed.")