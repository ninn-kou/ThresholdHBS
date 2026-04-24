import cmd
import json
import os

from tests.test_helpers import SignatureSchemeEnum, make_params
from threshold_hbs import SystemController

class SystemControllerCLI(cmd.Cmd):
    prompt = "> "

    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        self.signed_messages = [] 

    def do_status(self, arg):
        """Displays message queue status"""
        queued = len(self.controller.messages)
        capacity = self.controller.params.batching
        print(f"Message queue/batch status: {queued}/{capacity}")

    def do_queue(self, arg):
        """Queue message: queue <msg>"""
        if not arg:
            print("Err: msg required")
            return

        msg_bytes = arg.encode('utf-8')
        success = self.controller.queue_message(msg_bytes)
        
        if success:
            print("Message queued")
        else:
            print("Failed to queue message, batch reached full capacity")

    def do_sign(self, arg):
        """Attempts to sign a batch"""
        results = self.controller.sign_pending_batch()
        
        if results:
            start_index = len(self.signed_messages)
            self.signed_messages.extend(results)
            print(f"Signed {len(results)} message(s)")
            for i, (msg, _) in enumerate(results):
                print(f"[{start_index + i}] {msg.decode('utf-8')}")
        else:
            print("Failed to sign: batch must be full")

    def do_tree(self, arg):
        """Displays HyperTree usage status"""
        controller = self.controller
        
        upper_total = controller.params.num_leaves
        upper_used = controller.next_index
        
        bottom_total = controller.params.num_leaves
        
        if controller.cur_sharding_state is not None:
            bottom_used = sum(
                len(group.used_key_ids) 
                for group in controller.cur_sharding_state.coalition_map.values()
            )
        else:
            bottom_used = 0
            
        print(f"Upper tree capacity used: {upper_used}/{upper_total}")
        print(f"Bottom tree capacity used: {bottom_used}/{bottom_total}")

    def do_list(self, arg):
        """Displays a list of signed messages"""
        if not self.signed_messages:
            print("Empty")
            return
        
        for i, (msg, _) in enumerate(self.signed_messages):
            print(f"[{i}] {msg.decode('utf-8')}")

    def do_verify(self, arg):
        """Verifies a message given message and signature: verify <msg_index> <sig_index>"""
        args = arg.split()
        if not args:
            print("Please input index")
            return
            
        try:
            msg_index = int(args[0])
            sig_index = int(args[1]) if len(args) > 1 else msg_index
            
            max_index = len(self.signed_messages) - 1
            if msg_index < 0 or msg_index > max_index or sig_index < 0 or sig_index > max_index:
                print("Error: Invalid indices provided")
                return
            
            msg, _ = self.signed_messages[msg_index]
            _, sig = self.signed_messages[sig_index]
            
            is_valid = self.controller.verify_message(msg, sig)
            
            if is_valid:
                print(f"VALID: Message verified (using msg at [{msg_index}] and sig at [{sig_index}])")
            else:
                print(f"INVALID: Message did not pass verification (using msg at [{msg_index}] and sig at [{sig_index}])")
                
        except ValueError:
            print("Error: Invalid indices provided")

    def do_coalitions(self, arg):
        """Displays coalition groups and key usage"""
        state = self.controller.cur_sharding_state
        if not state:
            print("Error: no sharding state (lowkey should never happen)")
            return
            
        for members, group in state.coalition_map.items():
            used = len(group.used_key_ids)
            total = len(group.assigned_key_ids)
            print(f"[{', '.join(members)}]: {used}/{total} keys used")

    def do_quit(self, arg):
        """No description needed"""
        return True

def load_params_from_json():
    file_path = "config.json"
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Configuration file not found: {file_path}")
    
    with open(file_path, 'r') as file:
        data = json.load(file)
        
    print("Parameters Chosen:")
        
    scheme = data.get("signature_scheme", "Lamport").strip()
    
    if scheme == "Winternitz":
        scheme_enum = SignatureSchemeEnum.WINTERNITZ
        print("Signature Scheme: Winternitz Signature")
    else: 
        scheme_enum = SignatureSchemeEnum.LAMPORT
        print("Signature Scheme: Lamport Signature")
    
    batching = data.get("batching", 4)
    num_parties = data.get("num_parties", 3)
    threshold_k = data.get("threshold_k", 2)
    num_leaves = data.get("num_leaves", 2)
    
    print(f"Batching Parameter: {batching}")
    print(f"No. of Parties Parameter: {num_parties}")
    print(f"Threshold Parameter Parameter: {threshold_k}")
    print(f"No. of Leaves Parameter: {num_leaves}")
    
    return make_params(
        signature_scheme=scheme_enum,
        batching=data.get("batching", 4),
        num_parties=data.get("num_parties", 3),
        threshold_k=data.get("threshold_k", 2),
        num_leaves=data.get("num_leaves", 2)
    )
    
def main():
    print("Welcome to Threshold HBS CLI, Loading the parameters from config.json:")

    global_params = load_params_from_json()
    party_ids = [f"Signee_{i}" for i in range(1, global_params.num_parties + 1)]
    
    print("Type help for a list of commands")
    
    controller = SystemController(global_params, party_ids)
    
    cli = SystemControllerCLI(controller)
    cli.cmdloop()

if __name__ == '__main__':
    main()