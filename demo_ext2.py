from __future__ import annotations

from tests.test_helpers import make_params
from threshold_hbs.peer_to_peer import HelperStringServer, peer_to_peer_sign
from threshold_hbs.protocol import dealer_setup, verify_threshold_signature


def main() -> None:
    params = make_params(num_leaves=12, threshold_k=3, num_parties=5)
    party_ids = ["p0", "p1", "p2", "p3", "p4"]

    dealer_output, sharding_state = dealer_setup(params, party_ids)
    helper_server = HelperStringServer(dealer_output.common_reference_values)

    result = peer_to_peer_sign(
        b"peer-to-peer demo message",
        dealer_output,
        params,
        sharding_state,
        helper_server,
        proposer_id="p0",
        approval_policies={
            "p2": lambda proposal: (False, "p2 is offline for this message"),
        },
    )

    ok = verify_threshold_signature(
        b"peer-to-peer demo message",
        result.signature,
        dealer_output.composite_public_key,
        params,
    )
    tampered_ok = verify_threshold_signature(
        b"peer-to-peer demo message?",
        result.signature,
        dealer_output.composite_public_key,
        params,
    )

    print("proposal_by:", result.proposal.proposer_id)
    print("chosen_coalition:", result.decision.coalition)
    print("chosen_key_id:", result.decision.key_id)
    print("helper_server_lookups:", helper_server.lookup_log)
    print(
        "approved_parties:",
        sorted(
            [
                party_id
                for party_id, approval in result.decision.approvals.items()
                if approval.approved
            ]
        ),
    )
    print("verified(original):", ok)
    print("verified(tampered):", tampered_ok)


if __name__ == "__main__":
    main()
