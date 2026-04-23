from __future__ import annotations

import os
import time
import unittest

from tests.test_helpers import SignatureSchemeEnum, make_params
from threshold_hbs.merkle import (
    build_merkle_tree_signatures,
    get_auth_path,
    verify_merkle_path,
)
from threshold_hbs.protocol import (
    coalition_signature_scheme,
    dealer_setup,
    verify_threshold_signature,
)
from threshold_hbs.signatures.lamport import LamportSignatureScheme
from threshold_hbs.signatures.winternitz import WinternitzSignatureScheme

ITERATIONS = 1000
DIGEST_SIZE = 32
ELEMENT_SIZE = 32

def _banner(title: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}")

def _report(operation: str, iterations: int, total_s: float) -> None:
    avg_ms = (total_s / iterations) * 1000
    print(f"  {operation:<45} | {iterations:>6} iters | {total_s:>9.4f} s total | {avg_ms:>9.4f} ms/op")


class TestBenchmarkLamport(unittest.TestCase):
    """Benchmark Lamport key generation, signing, and verification."""

    def setUp(self) -> None:
        self.scheme = LamportSignatureScheme(DIGEST_SIZE, ELEMENT_SIZE)
        self.message = self.scheme.hash_message(b"benchmark payload")

    def test_keygen(self) -> None:
        _banner("Lamport — Key Generation")
        start = time.perf_counter()
        for _ in range(ITERATIONS):
            self.scheme.generate_keypair()
        elapsed = time.perf_counter() - start
        _report("lamport_keygen", ITERATIONS, elapsed)

    def test_sign(self) -> None:
        _banner("Lamport — Signing")
        # Pre-generate keypairs so we only time the sign call.
        keypairs = [self.scheme.generate_keypair() for _ in range(ITERATIONS)]

        start = time.perf_counter()
        for sk, _pk in keypairs:
            self.scheme.sign(self.message, sk)
        elapsed = time.perf_counter() - start
        _report("lamport_sign", ITERATIONS, elapsed)

    def test_verify(self) -> None:
        _banner("Lamport — Verification")
        # Pre-generate keypairs + signatures.
        triples = []
        for _ in range(ITERATIONS):
            sk, pk = self.scheme.generate_keypair()
            sig = self.scheme.sign(self.message, sk)
            triples.append((sig, pk))

        start = time.perf_counter()
        for sig, pk in triples:
            result = self.scheme.verify(self.message, sig, pk)
            self.assertTrue(result)
        elapsed = time.perf_counter() - start
        _report("lamport_verify", ITERATIONS, elapsed)


class TestBenchmarkWinternitz(unittest.TestCase):
    """Benchmark Winternitz key generation, signing, and verification."""

    def setUp(self) -> None:
        self.scheme = WinternitzSignatureScheme(DIGEST_SIZE, ELEMENT_SIZE, w=4)
        self.message = self.scheme.hash_message(b"benchmark payload")

    def test_keygen(self) -> None:
        _banner("Winternitz — Key Generation")
        start = time.perf_counter()
        for _ in range(ITERATIONS):
            self.scheme.generate_keypair()
        elapsed = time.perf_counter() - start
        _report("winternitz_keygen", ITERATIONS, elapsed)

    def test_sign(self) -> None:
        _banner("Winternitz — Signing")
        keypairs = [self.scheme.generate_keypair() for _ in range(ITERATIONS)]

        start = time.perf_counter()
        for sk, _pk in keypairs:
            self.scheme.sign(self.message, sk)
        elapsed = time.perf_counter() - start
        _report("winternitz_sign", ITERATIONS, elapsed)

    def test_verify(self) -> None:
        _banner("Winternitz — Verification")
        triples = []
        for _ in range(ITERATIONS):
            sk, pk = self.scheme.generate_keypair()
            sig = self.scheme.sign(self.message, sk)
            triples.append((sig, pk))

        start = time.perf_counter()
        for sig, pk in triples:
            result = self.scheme.verify(self.message, sig, pk)
            self.assertTrue(result)
        elapsed = time.perf_counter() - start
        _report("winternitz_verify", ITERATIONS, elapsed)

class TestBenchmarkProtocolSequence(unittest.TestCase):
    """Benchmark the full dealer-setup / coalition-sign / verify pipeline."""

    PARTY_IDS = ["Alice", "Bob", "Charlie", "Dave", "Eve"]

    def _run_sequence(self, scheme_enum: SignatureSchemeEnum, label: str) -> None:
        _banner(f"Protocol Sequence — {label}")
        params = make_params(
            num_parties=5,
            num_leaves=8,
            threshold_k=3,
            signature_scheme=scheme_enum,
        )

        # Setup
        t0 = time.perf_counter()
        dealer_output, sharding_state = dealer_setup(params, self.PARTY_IDS)
        t_setup = time.perf_counter() - t0
        _report(f"{label} dealer_setup", 1, t_setup)

        # Signing
        message = b"benchmark protocol message"
        t0 = time.perf_counter()
        signature = coalition_signature_scheme(
            message, dealer_output, params, sharding_state
        )
        t_sign = time.perf_counter() - t0
        _report(f"{label} coalition_sign", 1, t_sign)

        # Verification
        t0 = time.perf_counter()
        valid = verify_threshold_signature(
            message, signature, dealer_output.composite_public_key, params
        )
        t_verify = time.perf_counter() - t0
        self.assertTrue(valid)
        _report(f"{label} verify_threshold_signature", 1, t_verify)

        total = t_setup + t_sign + t_verify
        _report(f"{label} TOTAL (setup+sign+verify)", 1, total)

    def test_protocol_lamport(self) -> None:
        self._run_sequence(SignatureSchemeEnum.LAMPORT, "Lamport")

    def test_protocol_winternitz(self) -> None:
        self._run_sequence(SignatureSchemeEnum.WINTERNITZ, "Winternitz")


class TestBenchmarkMerkleConstruction(unittest.TestCase):
    """Benchmark Merkle tree construction across various leaf counts."""

    LEAF_COUNTS = [8, 64, 256, 1024]

    def test_merkle_tree_construction(self) -> None:
        _banner("Merkle Tree Construction")
        scheme = LamportSignatureScheme(DIGEST_SIZE, ELEMENT_SIZE)

        for n_leaves in self.LEAF_COUNTS:
            # Pre-generate public keys
            pks = [scheme.generate_keypair()[1] for _ in range(n_leaves)]

            start = time.perf_counter()
            tree, root = build_merkle_tree_signatures(pks)
            elapsed = time.perf_counter() - start

            self.assertIsNotNone(root)
            _report(f"build_merkle_tree_signatures (n={n_leaves})", 1, elapsed)



class TestBenchmarkMerkleVerification(unittest.TestCase):
    """Benchmark Merkle auth-path verification (1 000 iterations)."""

    def test_auth_path_verification(self) -> None:
        _banner("Merkle Auth-Path Verification")
        scheme = LamportSignatureScheme(DIGEST_SIZE, ELEMENT_SIZE)
        n_leaves = 1024
        pks = [scheme.generate_keypair()[1] for _ in range(n_leaves)]

        tree, root = build_merkle_tree_signatures(pks)

        # Pre-extract auth paths for ITERATIONS random leaves
        indices = [i % n_leaves for i in range(ITERATIONS)]
        auth_paths = [get_auth_path(tree, idx) for idx in indices]

        start = time.perf_counter()
        for idx, path in zip(indices, auth_paths):
            result = verify_merkle_path(pks[idx], idx, path, root)
            self.assertTrue(result)
        elapsed = time.perf_counter() - start
        _report("verify_merkle_path (1024 leaves)", ITERATIONS, elapsed)


if __name__ == "__main__":
    unittest.main()
