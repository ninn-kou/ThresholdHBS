from __future__ import annotations

import unittest

from threshold_hbs import (
    KeyReuseError,
    SystemParameters,
    aggregator_sign,
    benchmark_minimal_prototype,
    dealer_setup,
    verify_threshold_signature,
)
from threshold_hbs.models import ThresholdSignature


class PrototypeCompatibilityTests(unittest.TestCase):
    def make_params(self, num_leaves: int = 8) -> SystemParameters:
        return SystemParameters(
            num_parties=4,
            num_leaves=num_leaves,
            digest_size_bytes=8,
            lamport_element_size_bytes=16,
        )

    def test_end_to_end_signature_verifies(self) -> None:
        params = self.make_params()
        output = dealer_setup(params, [])
        message = b"hello"
        signature = aggregator_sign(message, 0, output, None, params)
        self.assertTrue(verify_threshold_signature(message, signature, output.composite_public_key, params))

    def test_tampered_message_fails(self) -> None:
        params = self.make_params()
        output = dealer_setup(params, [])
        signature = aggregator_sign(b"message", 0, output, None, params)
        self.assertFalse(verify_threshold_signature(b"different", signature, output.composite_public_key, params))

    def test_tampered_path_fails(self) -> None:
        params = self.make_params()
        output = dealer_setup(params, [])
        message = b"path"
        signature = aggregator_sign(message, 0, output, None, params)
        tampered_first = bytes([signature.auth_path[0][0] ^ 1]) + signature.auth_path[0][1:]
        tampered = ThresholdSignature(
            key_id=signature.key_id,
            randomizer=signature.randomizer,
            lamport_public_key=signature.lamport_public_key,
            lamport_signature_values=signature.lamport_signature_values,
            auth_path=[tampered_first] + signature.auth_path[1:],
        )
        self.assertFalse(verify_threshold_signature(message, tampered, output.composite_public_key, params))

    def test_key_reuse_is_rejected(self) -> None:
        params = self.make_params()
        output = dealer_setup(params, [])
        aggregator_sign(b"first", 0, output, None, params)
        with self.assertRaises(KeyReuseError):
            aggregator_sign(b"second", 0, output, None, params)

    def test_non_power_of_two_leaves_work(self) -> None:
        params = self.make_params(num_leaves=3)
        output = dealer_setup(params, [])
        signature = aggregator_sign(b"leaf-two", 2, output, None, params)
        self.assertTrue(verify_threshold_signature(b"leaf-two", signature, output.composite_public_key, params))

    def test_benchmark_output(self) -> None:
        params = self.make_params(num_leaves=4)
        output = dealer_setup(params, [])
        results = benchmark_minimal_prototype(params, [b"m0", b"m1", b"m2"], output)
        self.assertEqual(
            set(results.keys()),
            {
                "sign_total_s",
                "verify_total_s",
                "sign_avg_s",
                "verify_avg_s",
                "average_signature_size_bytes",
                "crv_size_bytes",
                "signatures_verified",
            },
        )
        self.assertEqual(results["signatures_verified"], 3.0)
        self.assertGreater(results["average_signature_size_bytes"], 0.0)
        self.assertGreater(results["crv_size_bytes"], 0.0)


if __name__ == "__main__":
    unittest.main()
