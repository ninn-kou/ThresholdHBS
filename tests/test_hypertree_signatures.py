from __future__ import annotations

import unittest

from tests.test_helpers import make_params
from threshold_hbs.SystemController import SystemController


class Extension4Tests(unittest.TestCase):
    # generate_coalitions
    def setUp(self):
        params = make_params(batching=1, num_parties=2, threshold_k=2)
        self.system_controller = SystemController(params, ['Alice', 'Bob'])

    def test1(self):
        self.system_controller.queue_message(b"abcd")
        msg, sig = self.system_controller.sign_pending_batch()[0]

        self.assertTrue(self.system_controller.verify_message(msg, sig))

    def test_verification_with_identical_message(self):
        self.system_controller.queue_message(b"abcd")
        msg1, sig1 = self.system_controller.sign_pending_batch()[0]
        
        self.system_controller.queue_message(b"abcd")
        msg2, sig2 = self.system_controller.sign_pending_batch()[0]
        
        self.assertTrue(self.system_controller.verify_message(msg2, sig1))

if __name__ == "__main__":
    unittest.main()