from __future__ import annotations

import unittest

from tests.test_helpers import SignatureSchemeEnum, make_params
from threshold_hbs import (
    dealer_setup,
)


from threshold_hbs.SystemController import SystemController
from threshold_hbs.merkle import build_merkle_tree_messages
import threshold_hbs.protocol as protocol
from threshold_hbs.signatures.lamport import LamportSignatureScheme
from threshold_hbs.signatures.winternitz import WinternitzSignatureScheme


class Extension4Tests(unittest.TestCase):
    # generate_coalitions
    def setUp(self):
        params = make_params(batching=1, num_parties=2, threshold_k=2)
        self.system_controller = SystemController(params, ['Alice', 'Bob'])

    def test1(self):
        self.system_controller.queue_message(b"abcd")
        msg, sig = self.system_controller.sign_pending_batch()[0]

        self.assertTrue(self.system_controller.verify_message(msg, sig))

    


if __name__ == "__main__":
    unittest.main()