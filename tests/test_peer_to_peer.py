from __future__ import annotations

import unittest

from test_helpers import make_params
from threshold_hbs.peer_to_peer import (
    HelperStringServer,
    NoApprovedCoalitionError,
    PeerMessageProposal,
    collect_peer_approvals,
    peer_to_peer_sign,
)
from threshold_hbs.protocol import dealer_setup, verify_threshold_signature


class Extension2PeerToPeerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.params = make_params(num_leaves=12, threshold_k=3, num_parties=5)
        self.party_ids = ["p0", "p1", "p2", "p3", "p4"]
        self.dealer_output, self.sharding_state = dealer_setup(self.params, self.party_ids)
        self.helper_server = HelperStringServer(self.dealer_output.common_reference_values)

    def test_collect_peer_approvals_default(self) -> None:
        approvals = collect_peer_approvals(
            proposal=PeerMessageProposal(proposer_id="p0", message=b"ship-it"),
            party_ids=self.party_ids,
        )
        self.assertEqual(set(approvals.keys()), set(self.party_ids))
        self.assertTrue(all(approval.approved for approval in approvals.values()))

    def test_peer_to_peer_sign_verifies(self) -> None:
        result = peer_to_peer_sign(
            b"peer-approved-message",
            self.dealer_output,
            self.params,
            self.sharding_state,
            self.helper_server,
            proposer_id="p0",
        )

        self.assertEqual(result.decision.coalition, ("p0", "p1", "p2"))
        self.assertEqual(result.decision.key_id, 0)
        self.assertEqual(self.helper_server.lookup_log, [0])
        self.assertTrue(
            verify_threshold_signature(
                b"peer-approved-message",
                result.signature,
                self.dealer_output.composite_public_key,
                self.params,
            )
        )

    def test_policy_rejection_moves_to_next_coalition(self) -> None:
        result = peer_to_peer_sign(
            b"message-needing-alt-coalition",
            self.dealer_output,
            self.params,
            self.sharding_state,
            self.helper_server,
            proposer_id="p0",
            approval_policies={
                "p2": lambda proposal: (False, "p2 refuses this message"),
            },
        )

        self.assertEqual(result.decision.coalition, ("p0", "p1", "p3"))
        self.assertEqual(result.decision.key_id, 1)
        self.assertEqual(self.helper_server.lookup_log, [1])
        self.assertTrue(
            verify_threshold_signature(
                b"message-needing-alt-coalition",
                result.signature,
                self.dealer_output.composite_public_key,
                self.params,
            )
        )

    def test_no_approved_coalition_raises(self) -> None:
        with self.assertRaises(NoApprovedCoalitionError):
            peer_to_peer_sign(
                b"blocked-message",
                self.dealer_output,
                self.params,
                self.sharding_state,
                self.helper_server,
                proposer_id="p0",
                approval_policies={
                    "p2": lambda proposal: False,
                    "p3": lambda proposal: False,
                    "p4": lambda proposal: False,
                },
            )


if __name__ == "__main__":
    unittest.main()
