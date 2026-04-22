from __future__ import annotations

import unittest

from tests.test_helpers import SignatureSchemeEnum, make_params
from threshold_hbs import (
    dealer_setup,
)


from threshold_hbs.merkle import build_merkle_tree_messages
import threshold_hbs.protocol as protocol
from threshold_hbs.signatures.lamport import LamportSignatureScheme
from threshold_hbs.signatures.winternitz import WinternitzSignatureScheme


class Extension3Tests(unittest.TestCase):
    # generate_coalitions
    def setUp(self):
        self.params = make_params()
        self.parties = ['p0', 'p1', 'p2', 'p3', 'p4']
        self.dealer_output, self.sharding_state = dealer_setup(self.params, self.parties)

    def test_batch_signatures_success(self) -> None:
        messages = [b"m1", b"m2", b"m3"]
        
        batch_signatures = protocol.batch_coalition_signature_scheme(
            messages, self.dealer_output, self.params, self.sharding_state
        )
        
        self.assertEqual(len(batch_signatures), len(messages))
        for i in range(len(messages)):
            self.assertTrue(protocol.verify_batch_signature(
                messages[i], 
                batch_signatures[i], 
                self.dealer_output.composite_public_key, 
                self.params
            ))

    def test_batch_signature_bad_message(self) -> None:
        messages = [b"m1", b"m2", b"m3"]
        batch_signatures = protocol.batch_coalition_signature_scheme(
            messages, self.dealer_output, self.params, self.sharding_state
        )
        
        bad_message = b"m1_bad"

        self.assertFalse(protocol.verify_batch_signature(
            bad_message, 
            batch_signatures[0], 
            self.dealer_output.composite_public_key, 
            self.params
        ))

    def test_batch_signature_mismatched_signature(self) -> None:
        messages = [b"m1", b"m2", b"m3"]
        batch_signatures = protocol.batch_coalition_signature_scheme(
            messages, self.dealer_output, self.params, self.sharding_state
        )
        
        self.assertFalse(protocol.verify_batch_signature(
            messages[0], 
            batch_signatures[1], 
            self.dealer_output.composite_public_key, 
            self.params
        ))

    def test_batch_signature_single_message(self) -> None:
        messages = [b"single_message"]
        batch_signatures = protocol.batch_coalition_signature_scheme(
            messages, self.dealer_output, self.params, self.sharding_state
        )
        
        self.assertEqual(len(batch_signatures), 1)
        self.assertTrue(protocol.verify_batch_signature(
            messages[0], 
            batch_signatures[0], 
            self.dealer_output.composite_public_key, 
            self.params
        ))

    def test_batch_signature_large_batch(self) -> None:
        messages = [f"msg_{i}".encode('utf-8') for i in range(10)]
        batch_signatures = protocol.batch_coalition_signature_scheme(
            messages, self.dealer_output, self.params, self.sharding_state
        )
        
        self.assertEqual(len(batch_signatures), 10)
        for i in range(len(messages)):
            self.assertTrue(protocol.verify_batch_signature(
                messages[i], 
                batch_signatures[i], 
                self.dealer_output.composite_public_key, 
                self.params
            ))


if __name__ == "__main__":
    unittest.main()