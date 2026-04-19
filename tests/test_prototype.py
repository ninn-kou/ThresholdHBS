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

from threshold_hbs.extensions.sharding import (
    generate_coalitions,
    assign_keys_to_all_coalitions,
    select_signing_coalition_and_key,
    dealer_setup_ext1
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


class Extension1Tests(unittest.TestCase):
    def make_params(self, num_leaves: int = 8) -> SystemParameters:
        return SystemParameters(
            num_parties=5,
            num_leaves=num_leaves,
            threshold_k=3,
            digest_size_bytes=8,
            lamport_element_size_bytes=16,
        )

    # generate_coalitions
    def test_coalition_generation(self) -> None:
        params = self.make_params()
        coalition_groups = generate_coalitions(params, ['p0', 'p1', 'p2', 'p3', 'p4'])
        self.assertEqual(len(coalition_groups), 10)

    def test_coalition_generation_error_wrong_parties(self) -> None:
        params = self.make_params()
        with self.assertRaises(ValueError):
            generate_coalitions(params, ['p0', 'p1', 'p2', 'p3', 'p4', 'p5'])

    def test_coalition_generation_error_wrong_threshold(self) -> None:
        params = SystemParameters(
            num_parties=5,
            num_leaves=8,
            threshold_k=6,
            digest_size_bytes=8,
            lamport_element_size_bytes=16,
        )
        with self.assertRaises(ValueError):
            generate_coalitions(params, ['p0', 'p1', 'p2', 'p3', 'p4'])

    # assign_keys_to_all_coalitions
    def test_key_assignment_to_coalition(self) -> None:
        params = self.make_params()
        coalition_groups = generate_coalitions(params, ['p0', 'p1', 'p2', 'p3', 'p4'])
        shardingState = assign_keys_to_all_coalitions(params, coalition_groups)
        self.assertEqual(len(coalition_groups), 10)
        self.assertEqual(len(shardingState.coalition_map), 10)
        self.assertEqual(len(shardingState.key_to_coalition), 8)
        self.assertEqual(
            shardingState.key_to_coalition, 
            {
                0: ('p0', 'p1', 'p2'),
                1: ('p0', 'p1', 'p3'),
                2: ('p0', 'p1', 'p4'),
                3: ('p0', 'p2', 'p3'),
                4: ('p0', 'p2', 'p4'),
                5: ('p0', 'p3', 'p4'),
                6: ('p1', 'p2', 'p3'),
                7: ('p1', 'p2', 'p4'),
            }
        )

        # how do i test the rest of the two?
    def test_key_assignment_to_coalition_1(self) -> None:
        params = SystemParameters(
            num_parties=5,
            num_leaves=15,
            threshold_k=3,
            digest_size_bytes=8,
            lamport_element_size_bytes=16,
        )
        coalition_groups = generate_coalitions(params, ['p0', 'p1', 'p2', 'p3', 'p4'])
        shardingState = assign_keys_to_all_coalitions(params, coalition_groups)
        self.assertEqual(len(coalition_groups), 10)
        self.assertEqual(len(shardingState.coalition_map), 10)
        self.assertEqual(len(shardingState.key_to_coalition), 15)
        self.assertEqual(
            shardingState.key_to_coalition, 
            {
                0: ('p0', 'p1', 'p2'),
                1: ('p0', 'p1', 'p3'),
                2: ('p0', 'p1', 'p4'),
                3: ('p0', 'p2', 'p3'),
                4: ('p0', 'p2', 'p4'),
                5: ('p0', 'p3', 'p4'),
                6: ('p1', 'p2', 'p3'),
                7: ('p1', 'p2', 'p4'),
                8: ('p1', 'p3', 'p4'),
                9: ('p2', 'p3', 'p4'),
                10: ('p0', 'p1', 'p2'),
                11: ('p0', 'p1', 'p3'),
                12: ('p0', 'p1', 'p4'),
                13: ('p0', 'p2', 'p3'),
                14: ('p0', 'p2', 'p4')
            }
        )

    def test_key_assignment_to_coalition_2(self) -> None:
        params = SystemParameters(
            num_parties=5,
            num_leaves=15,
            threshold_k=3,
            digest_size_bytes=8,
            lamport_element_size_bytes=16,
        )
        coalition_groups = generate_coalitions(params, ['p0', 'p1', 'p2', 'p3', 'p4'])
        shardingState = assign_keys_to_all_coalitions(params, coalition_groups)

        self.assertEqual(len(shardingState.key_to_coalition), params.num_leaves)

        for key_id, coalition in shardingState.key_to_coalition.items():
            self.assertIn(coalition, shardingState.coalition_map)

        for key_id, coalition in shardingState.key_to_coalition.items():
            self.assertIn(key_id, shardingState.coalition_map[coalition].assigned_key_ids)


    def test_select_signing_coalition_and_key(self) -> None:
        params = SystemParameters(
            num_parties=5,
            num_leaves=15,
            threshold_k=3,
            digest_size_bytes=8,
            lamport_element_size_bytes=16,
        )
        coalition_groups = generate_coalitions(params, ['p0', 'p1', 'p2', 'p3', 'p4'])
        assign_keys_to_all_coalitions(params, coalition_groups)
        coalition_group, key = select_signing_coalition_and_key(coalition_groups)

        self.assertIn(coalition_group, coalition_groups)
        self.assertIn(key, coalition_group.assigned_key_ids)
        self.assertIn(key, coalition_group.used_key_ids)

    
    def test_select_signing_coalition_and_key_exhaust(self) -> None:
        params = SystemParameters(
            num_parties=5,
            num_leaves=15,
            threshold_k=3,
            digest_size_bytes=8,
            lamport_element_size_bytes=16,
        )
        coalition_groups = generate_coalitions(params, ['p0', 'p1', 'p2', 'p3', 'p4'])
        assign_keys_to_all_coalitions(params, coalition_groups)

        for _ in range(params.num_leaves):
            select_signing_coalition_and_key(coalition_groups)
        
        with self.assertRaises(ValueError):
            select_signing_coalition_and_key(coalition_groups)


    def test_dealer_setup_ext1(self) -> None:
        params = self.make_params()
        dealer_output, sharding_state = dealer_setup_ext1(params, ['p0', 'p1', 'p2', 'p3', 'p4'])

        self.assertEqual(len(dealer_output.members), 5)
        self.assertEqual(len(sharding_state.key_to_coalition), params.num_leaves)
        self.assertEqual(len(dealer_output.common_reference_values), params.num_leaves)

        for key_id, coalition in sharding_state.key_to_coalition.items():
            self.assertIsNotNone(dealer_output.common_reference_values[key_id])

            for party_id, trustee in dealer_output.members.items():
                has_share = any(share.key_id == key_id for share in trustee.shares)
                
                if party_id in coalition:
                    self.assertTrue(has_share, f"{party_id} should have share for key {key_id}")
                else: 
                    self.assertFalse(has_share, f"{party_id} should not have share for key {key_id}")



if __name__ == "__main__":
    unittest.main()
