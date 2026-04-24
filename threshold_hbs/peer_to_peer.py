from __future__ import annotations

"""Peer-to-peer coordination for Extension 2.

Author: Hao Ren
zID: z5237203

This module keeps the existing cryptographic signing path unchanged and adds a
coordination layer on top of the current sharded signing flow:

- trustees approve or reject a proposed message locally,
- the participating coalition is selected from the approved trustees,
- the untrusted helper server is used only to look up helper-string / CRV material,
- the final signature is still produced by the existing threshold signing code.

The implementation is intentionally stand-alone so it can be merged without
changing protocol.py, SystemController.py, or the Extension 3/4/5 paths.
"""

from dataclasses import dataclass
from typing import Callable, Dict, Mapping, Optional, Sequence, Tuple

from .exceptions import SigningRefusedError
from .models import CommonReferenceValue, DealerOutput, ShardingState, SystemParameters, ThresholdSignature
from .protocol import aggregator_sign


class PeerCoordinationError(SigningRefusedError):
    """Raised when peer-to-peer coordination fails before signing begins."""


class NoApprovedCoalitionError(PeerCoordinationError):
    """Raised when no fully approved coalition with an unused key_id exists."""


@dataclass(frozen=True)
class PeerMessageProposal:
    """A message proposed for peer approval."""

    proposer_id: str
    message: bytes


@dataclass(frozen=True)
class PeerApproval:
    """One trustee's local decision about a proposal."""

    party_id: str
    approved: bool
    reason: str = ""


@dataclass(frozen=True)
class PeerSigningDecision:
    """The coalition and key selected by the peer layer."""

    coalition: Tuple[str, ...]
    key_id: int
    approvals: Dict[str, PeerApproval]


@dataclass(frozen=True)
class PeerToPeerSignatureResult:
    """Outcome of a peer-to-peer coordinated signing run."""

    proposal: PeerMessageProposal
    decision: PeerSigningDecision
    signature: ThresholdSignature


class HelperStringServer:
    """Untrusted helper-string / CRV lookup service.

    The server only exposes CRV/helper-string lookup. It does not decide which
    message is signed or which coalition participates.
    """

    def __init__(self, common_reference_values: Sequence[CommonReferenceValue]) -> None:
        self._common_reference_values = list(common_reference_values)
        self.lookup_log: list[int] = []

    def lookup_crv(self, key_id: int) -> CommonReferenceValue:
        if not (0 <= key_id < len(self._common_reference_values)):
            raise IndexError(f"key_id {key_id} is out of range for helper-string lookup")
        self.lookup_log.append(key_id)
        return self._common_reference_values[key_id]


ApprovalPolicy = Callable[[PeerMessageProposal], bool | tuple[bool, str]]

def _evaluate_policy(
    party_id: str,
    proposal: PeerMessageProposal,
    approval_policies: Optional[Mapping[str, ApprovalPolicy]] = None,
) -> PeerApproval:
    # default to approval if no policy is provided for this trustee
    if approval_policies is None or party_id not in approval_policies:
        return PeerApproval(party_id=party_id, approved=True, reason="default-approve")

    decision = approval_policies[party_id](proposal)
    if isinstance(decision, tuple):
        approved, reason = decision
        return PeerApproval(party_id=party_id, approved=bool(approved), reason=str(reason))
    return PeerApproval(
        party_id=party_id,
        approved=bool(decision),
        reason="policy-approve" if decision else "policy-reject",
    )


def collect_peer_approvals(
    proposal: PeerMessageProposal,
    party_ids: Sequence[str],
    approval_policies: Optional[Mapping[str, ApprovalPolicy]] = None,
) -> Dict[str, PeerApproval]:
    """Collect point-to-point approvals from trustees.

    In this prototype the peer-to-peer exchange is simulated locally with direct
    function calls. The important separation is architectural: trustees decide on
    the message and eligible coalition here, before the helper server is queried.
    """
    return {
        party_id: _evaluate_policy(party_id, proposal, approval_policies)
        for party_id in party_ids
    }


def select_peer_coalition_and_key(
    approvals: Mapping[str, PeerApproval],
    sharding_state: ShardingState,
    preferred_coalition: Optional[Tuple[str, ...]] = None,
) -> Tuple[Tuple[str, ...], int]:
    """Choose a fully approved coalition and reserve one of its unused key_ids."""
    approved_parties = {
        party_id
        for party_id, approval in approvals.items()
        if approval.approved
    }

    if preferred_coalition is not None:
        candidate_items = [(preferred_coalition, sharding_state.coalition_map.get(preferred_coalition))]
    else:
        candidate_items = list(sharding_state.coalition_map.items())

    for coalition, group in candidate_items:
        if group is None:
            continue
        # candidate coalitions must be fully approved before signing
        if not set(coalition).issubset(approved_parties):
            continue

        for key_id in group.assigned_key_ids:
            if key_id not in group.used_key_ids:
                # reserve the key_id to preserve one-time key usage
                group.used_key_ids.add(key_id)
                return coalition, key_id

    raise NoApprovedCoalitionError("no fully approved coalition with an unused key_id exists")


def _subset_dealer_output_for_coalition(
    dealer_output: DealerOutput,
    coalition: Tuple[str, ...],
    key_id: int,
    helper_server: HelperStringServer,
) -> DealerOutput:
    # restrict signing state to trustees in the selected coalition
    group_members = {
        name: trustee
        for name, trustee in dealer_output.members.items()
        if name in coalition
    }
    if len(group_members) != len(coalition):
        raise PeerCoordinationError("selected coalition is missing one or more trustee states")

    helper_backed_crv = list(dealer_output.common_reference_values)
    # fetch CRV/helper-string material from the untrusted helper server only after approval
    helper_backed_crv[key_id] = helper_server.lookup_crv(key_id)

    return DealerOutput(
        party_id=dealer_output.party_id,
        composite_public_key=dealer_output.composite_public_key,
        common_reference_values=helper_backed_crv,
        public_keys_by_key_id=dealer_output.public_keys_by_key_id,
        members=group_members,
        used_keys=dealer_output.used_keys,
    )


def peer_to_peer_sign(
    message: bytes,
    dealer_output: DealerOutput,
    params: SystemParameters,
    sharding_state: ShardingState,
    helper_server: HelperStringServer,
    proposer_id: str = "peer",
    approval_policies: Optional[Mapping[str, ApprovalPolicy]] = None,
    preferred_coalition: Optional[Tuple[str, ...]] = None,
) -> PeerToPeerSignatureResult:
    """Extension 2 signing entry point.

    Flow:
    1. A proposer broadcasts a message to trustees.
    2. Trustees approve or reject locally.
    3. The peer layer selects a coalition and key_id from the approved trustees.
    4. Only then is the untrusted helper server queried for the CRV/helper string.
    5. The existing signing flow combines the selected trustees' shares.
    """
    proposal = PeerMessageProposal(proposer_id=proposer_id, message=message)
    approvals = collect_peer_approvals(proposal, list(dealer_output.members.keys()), approval_policies)
    coalition, key_id = select_peer_coalition_and_key(approvals, sharding_state, preferred_coalition)

    selected_bundle = _subset_dealer_output_for_coalition(dealer_output, coalition, key_id, helper_server)
    signature = aggregator_sign(message, key_id, selected_bundle, None, params)

    return PeerToPeerSignatureResult(
        proposal=proposal,
        decision=PeerSigningDecision(coalition=coalition, key_id=key_id, approvals=dict(approvals)),
        signature=signature,
    )


__all__ = [
    "ApprovalPolicy",
    "HelperStringServer",
    "NoApprovedCoalitionError",
    "PeerApproval",
    "PeerCoordinationError",
    "PeerMessageProposal",
    "PeerSigningDecision",
    "PeerToPeerSignatureResult",
    "collect_peer_approvals",
    "peer_to_peer_sign",
    "select_peer_coalition_and_key",
]
