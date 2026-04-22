from typing import Dict, List, Sequence, Tuple

from threshold_hbs.merkle import build_merkle_tree_messages, build_merkle_tree_signatures, verify_merkle_path
from threshold_hbs.models import BatchSignature, SystemParameters, ThresholdSignature
from threshold_hbs.protocol import batch_coalition_signature_scheme, dealer_setup, verify_batch_signature


class SystemController:

    def __init__(self, global_params: SystemParameters, party_ids: Sequence[str]):
        self.params = global_params
        self.active_bottom_tree = dealer_setup(global_params, party_ids)
        self.messages: List[bytes] = []


    def queue_message(self, message: bytes) -> bool:
        if len(self.messages) > self.params.batching:
            return False
        else :
            self.messages.append(message)
            return True
        
    def verify_message(self, message: bytes, signature: BatchSignature) -> bool:
        root_public_key = self.active_bottom_tree[0].composite_public_key
        return verify_batch_signature(message, signature, root_public_key, self.params)
    
    def sign_pending_batch(self) -> List[Tuple[bytes, BatchSignature]] | None:
        if len(self.messages) != self.params.batching:
            return None
        else:
            signatures = batch_coalition_signature_scheme(self.messages, self.active_bottom_tree[0], self.params, self.active_bottom_tree[1])
            output = list(zip(self.messages, signatures))
            print(output)
            self.messages = []
            return output