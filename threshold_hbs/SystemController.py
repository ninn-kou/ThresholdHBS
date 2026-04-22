import os
from typing import Dict, List, Sequence, Tuple

from threshold_hbs.merkle import build_merkle_tree_messages, build_merkle_tree_signatures, get_auth_path, verify_merkle_path
from threshold_hbs.models import BatchSignature, HyperTreeSignature, SystemParameters, ThresholdSignature, UpperTreeSignature
from threshold_hbs.protocol import batch_coalition_signature_scheme, dealer_setup, verify_batch_signature
from threshold_hbs.sharing import signing_digest_bytes


class SystemController:

    def __init__(self, global_params: SystemParameters, party_ids: Sequence[str]):
        self.params = global_params
        self.active_bottom_tree = dealer_setup(global_params, party_ids)
        self.messages: List[bytes] = []

        self.party_ids = party_ids
        self.secret_keys = []
        self.public_keys = []

        for _ in range(global_params.num_leaves):
            sk, pk = global_params.signature_scheme.generate_keypair()
            self.secret_keys.append(sk)
            self.public_keys.append(pk)

        self.tree, self.tree_root = build_merkle_tree_signatures(self.public_keys, global_params.hash_name)
        self.next_index = 0
        self.cur_bottom_root = self.cur_dealer_output = self.cur_sharding_state = self.upper_tree_signature = None

        self._create_bottom_tree()

    def _create_bottom_tree(self):
       if self.next_index >= self.params.num_leaves:
           pass
       
       dealer_output, sharding_state = dealer_setup(self.params, self.party_ids)
       bottom_root = dealer_output.composite_public_key

       index = self.next_index
       self.index += 1
       sk = self.secret_keys[index]

       randomizer = os.urandom(self.params.digest_size_bytes)
       h = signing_digest_bytes(
            message=bottom_root, 
            key_id=index, 
            randomizer=randomizer, 
            digest_size_bytes=self.params.digest_size_bytes, 
            hash_name=self.params.hash_name
        )
       
       signature = self.params.signature_scheme.sign(h, sk)
       path = get_auth_path(self.tree, index)

       self.upper_tree_signature = UpperTreeSignature(
           key_id=index,
           bottom_root=bottom_root,
           public_key=self.public_keys[index],
           randomizer=randomizer,
           signature_values=signature,
           auth_path=path
       )

       self.cur_dealer_output = dealer_output
       self.cur_sharding_state = sharding_state
       self.cur_bottom_root = bottom_root

    def queue_message(self, message: bytes) -> bool:
        if len(self.messages) > self.params.batching:
            return False
        else :
            self.messages.append(message)
            return True
        
    def verify_message(self, message: bytes, signature: HyperTreeSignature) -> bool:
        bottom_root = signature.upper_tree_signature.bottom_root
        
        is_batch_valid = verify_batch_signature(
            message=message, 
            batch_signatures=signature.batch_signature, 
            root_public_key=bottom_root, 
            params=self.params
        )
        if not is_batch_valid:
            return False
            
        upper_sig = signature.upper_tree_signature
        
        h = signing_digest_bytes(
            message=upper_sig.bottom_root, 
            key_id=upper_sig.key_id, 
            randomizer=upper_sig.randomizer, 
            digest_size_bytes=self.params.digest_size_bytes, 
            hash_name=self.params.hash_name
        )
        
        is_valid_sig = self.params.signature_scheme.verify(
            h, 
            upper_sig.signature_values, 
            upper_sig.public_key
        )
        if not is_valid_sig:
            return False

        is_path_valid = verify_merkle_path(
            leaf_public_key=upper_sig.public_key,
            key_id=upper_sig.key_id,
            auth_path=upper_sig.auth_path,
            root_public_key=self.tree_root,
            hash_name=self.params.hash_name
        )
        
        return is_path_valid
    
    def sign_pending_batch(self) -> List[Tuple[bytes, HyperTreeSignature]] | None:
        if len(self.messages) != self.params.batching:
            return None

        batch_signatures = batch_coalition_signature_scheme(
            messages=self.messages, 
            dealer_output=self.cur_dealer_output, 
            params=self.params, 
            sharding_state=self.cur_sharding_state
        )
        
        full_signatures = []
        for batch_sig in batch_signatures:
            full_sig = HyperTreeSignature(
                batch_signature=batch_sig,
                upper_tree_signature=self.upper_tree_signature
            )
            full_signatures.append(full_sig)

        output = list(zip(self.messages, full_signatures))
        self.messages = []
        return output
        
    