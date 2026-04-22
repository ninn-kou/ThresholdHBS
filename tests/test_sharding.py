from __future__ import annotations

import unittest

from threshold_hbs import (
    SystemParameters,
    verify_threshold_signature,
)

from threshold_hbs.extensions.sharding import (
    coalition_signature_scheme,
    generate_coalitions,
    assign_keys_to_all_coalitions,
    select_signing_coalition_and_key,
    dealer_setup_ext1
) 

import threshold_hbs.protocol as protocol


class Extension1Tests(unittest.TestCase):
    def setUp(self) -> None:
        protocol.signature_scheme = None

    def make_params(self, num_leaves: int = 8) -> SystemParameters:
        return SystemParameters(
            num_parties=5,
            num_leaves=num_leaves,
            threshold_k=3,
            digest_size_bytes=32,
            lamport_element_size_bytes=32,
        )

    # generate_coalitions
    def test_coalition_generation(self) -> None:
        params = self.make_params()
        coalition_groups = generate_coalitions(params, ['p0', 'p1', 'p2', 'p3', 'p4'])
        self.assertEqual(len(coalition_groups), 10)
    

    def test_coalition_generation_exact(self) -> None:
        params = self.make_params()
        coalition_groups = generate_coalitions(params, ['p0', 'p1', 'p2', 'p3', 'p4'])
        actual = [group.group_members for group in coalition_groups]
        expected = [
            ('p0', 'p1', 'p2'),
            ('p0', 'p1', 'p3'),
            ('p0', 'p1', 'p4'),
            ('p0', 'p2', 'p3'),
            ('p0', 'p2', 'p4'),
            ('p0', 'p3', 'p4'),
            ('p1', 'p2', 'p3'),
            ('p1', 'p2', 'p4'),
            ('p1', 'p3', 'p4'),
            ('p2', 'p3', 'p4')
        ]
        self.assertEqual(actual, expected)


    def test_coalition_generation_error_wrong_parties(self) -> None:
        params = self.make_params()
        with self.assertRaises(ValueError):
            generate_coalitions(params, ['p0', 'p1', 'p2', 'p3', 'p4', 'p5'])

    def test_coalition_generation_error_wrong_threshold(self) -> None:
        params = SystemParameters(
            num_parties=5,
            num_leaves=8,
            threshold_k=6,
            digest_size_bytes=32,
            lamport_element_size_bytes=32,
        )
        with self.assertRaises(ValueError):
            generate_coalitions(params, ['p0', 'p1', 'p2', 'p3', 'p4'])

    # assign_keys_to_all_coalitions
    def test_assign_keys_to_all_coalitions(self) -> None:
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

    def test_assign_keys_to_all_coalitions_1(self) -> None:
        params = self.make_params(num_leaves=15)
        coalition_groups = generate_coalitions(params, ['p0', 'p1', 'p2', 'p3', 'p4'])
        sharding_state = assign_keys_to_all_coalitions(params, coalition_groups)
        self.assertEqual(len(coalition_groups), 10)
        self.assertEqual(len(sharding_state.coalition_map), 10)
        self.assertEqual(len(sharding_state.key_to_coalition), 15)
        self.assertEqual(
            sharding_state.key_to_coalition, 
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

    def test_assign_keys_to_all_coalitions_2(self) -> None:
        params = self.make_params(num_leaves=15)
        coalition_groups = generate_coalitions(params, ['p0', 'p1', 'p2', 'p3', 'p4'])
        sharding_state = assign_keys_to_all_coalitions(params, coalition_groups)

        self.assertEqual(len(sharding_state.key_to_coalition), params.num_leaves)

        for key_id, coalition in sharding_state.key_to_coalition.items():
            self.assertIn(coalition, sharding_state.coalition_map)

        for key_id, coalition in sharding_state.key_to_coalition.items():
            self.assertIn(key_id, sharding_state.coalition_map[coalition].assigned_key_ids)


    def test_assign_keys_to_all_coalitions_exact_1(self) -> None:
        params = self.make_params(num_leaves=15)
        coalition_groups = generate_coalitions(params, ['p0', 'p1', 'p2', 'p3', 'p4'])
        sharding_state = assign_keys_to_all_coalitions(params, coalition_groups)

        self.assertEqual(
            sharding_state.coalition_map[('p0', 'p1', 'p2')].assigned_key_ids, [0, 10]
        )

        self.assertEqual(
            sharding_state.coalition_map[('p1', 'p2', 'p4')].assigned_key_ids, [7]
        )


    def test_assign_keys_to_all_coalitions_exact_2(self) -> None:
        params = self.make_params()
        coalition_groups = generate_coalitions(params, ['p0', 'p1', 'p2', 'p3', 'p4'])
        sharding_state = assign_keys_to_all_coalitions(params, coalition_groups)

        self.assertEqual(
            sharding_state.coalition_map[('p0', 'p1', 'p2')].assigned_key_ids, [0]
        )

        self.assertEqual(
            sharding_state.coalition_map[('p1', 'p2', 'p4')].assigned_key_ids, [7]
        )

        self.assertEqual(
            sharding_state.coalition_map[('p1', 'p3', 'p4')].assigned_key_ids, []
        )

        self.assertEqual(
            sharding_state.coalition_map[('p2', 'p3', 'p4')].assigned_key_ids, []
        )


    def test_select_signing_coalition_and_key(self) -> None:
        params = self.make_params(num_leaves=15)
        coalition_groups = generate_coalitions(params, ['p0', 'p1', 'p2', 'p3', 'p4'])
        assign_keys_to_all_coalitions(params, coalition_groups)
        coalition_group, key = select_signing_coalition_and_key(coalition_groups)

        self.assertIn(coalition_group, coalition_groups)
        self.assertIn(key, coalition_group.assigned_key_ids)
        self.assertIn(key, coalition_group.used_key_ids)

    
    def test_select_signing_coalition_and_key_exhaust(self) -> None:
        params = self.make_params(num_leaves=15)
        coalition_groups = generate_coalitions(params, ['p0', 'p1', 'p2', 'p3', 'p4'])
        assign_keys_to_all_coalitions(params, coalition_groups)

        for _ in range(params.num_leaves):
            select_signing_coalition_and_key(coalition_groups)
        
        with self.assertRaises(ValueError):
            select_signing_coalition_and_key(coalition_groups)


    def test_select_signing_coalition_and_key_exact(self) -> None:
        params = self.make_params(num_leaves=15)
        coalition_groups = generate_coalitions(params, ['p0', 'p1', 'p2', 'p3', 'p4'])
        assign_keys_to_all_coalitions(params, coalition_groups)

        # default first one
        group, key_id = select_signing_coalition_and_key(coalition_groups)
        self.assertEqual(group.group_members, ('p0', 'p1', 'p2'))
        self.assertEqual(key_id, 0)
        self.assertIn(0, group.used_key_ids)

        # second
        group, key_id = select_signing_coalition_and_key(coalition_groups)
        self.assertEqual(group.group_members, ('p0', 'p1', 'p2'))
        self.assertEqual(key_id, 10)
        self.assertIn(0, group.used_key_ids)
        self.assertIn(10, group.used_key_ids)

        # third
        group, key_id = select_signing_coalition_and_key(coalition_groups)
        self.assertEqual(group.group_members, ('p0', 'p1', 'p3'))
        self.assertEqual(key_id, 1)
        self.assertIn(1, group.used_key_ids)



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


    def test_dealer_setup_ext1_exact(self) -> None:
        params = self.make_params()
        dealer_output, sharding_state = dealer_setup_ext1(params, ['p0', 'p1', 'p2', 'p3', 'p4'])

        # check key id in TrusteeShareKeys
        self.assertEqual(sharding_state.key_to_coalition[0], ('p0', 'p1', 'p2'))
        self.assertTrue(any(s.key_id == 0 for s in dealer_output.members['p0'].shares))
        self.assertTrue(any(s.key_id == 0 for s in dealer_output.members['p1'].shares))
        self.assertTrue(any(s.key_id == 0 for s in dealer_output.members['p2'].shares))
        self.assertFalse(any(s.key_id == 0 for s in dealer_output.members['p3'].shares))
        self.assertFalse(any(s.key_id == 0 for s in dealer_output.members['p4'].shares))


    def test_coalition_signature_scheme(self) -> None:
        message_1 = b"hello"
        message_2 = b"hello?"
        params = self.make_params()
        dealer_output, sharding_state = dealer_setup_ext1(params, ['p0', 'p1', 'p2', 'p3', 'p4'])
        threshold_signature = coalition_signature_scheme(message_1, dealer_output, params, sharding_state)
        # true
        self.assertTrue(verify_threshold_signature(message_1, threshold_signature, dealer_output.composite_public_key, params))
        # false - as the signature is valid for message_1
        self.assertFalse(verify_threshold_signature(message_2, threshold_signature, dealer_output.composite_public_key, params))


    def test_coalition_signature_scheme_multiple_and_exhaust(self) -> None:
        params = self.make_params(num_leaves=5)
        dealer_output, sharding_state = dealer_setup_ext1(params, ['p0', 'p1', 'p2', 'p3', 'p4'])

        # multiple signatures
        for i in range(5):
            message = f"hello-{i}".encode()
            threshold_signature = coalition_signature_scheme(message, dealer_output, params, sharding_state)
            self.assertTrue(verify_threshold_signature(message, threshold_signature, dealer_output.composite_public_key, params))

        # exhaust check
        with self.assertRaises(ValueError):
            coalition_signature_scheme(b"extra message", dealer_output, params, sharding_state)
    


if __name__ == "__main__":
    unittest.main()