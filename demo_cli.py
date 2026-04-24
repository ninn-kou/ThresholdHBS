import cmd

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
        print(f"{queued}/{capacity}")

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
                print("VALID: Message verified")
            else:
                print("INVALID: Message did not pass verification")
                
        except ValueError:
            print("Error: Invalid indices provided")

    def do_quit(self, arg):
        """No description needed"""
        return True

def main():
    print("Welcome to Threshold HBS CLI, Please choose a Signature Scheme:")
    print("1: Lamport, 2: Winternitz")
    
    while True:
        choice = input("> ").strip()
        if choice in ['1', '2']:
            break
        print("Invalid choice")

    signature = None
    if choice == '1':
        signature = SignatureSchemeEnum.LAMPORT
        print("Lamport Signature Scheme selected")
    else:
        signature = SignatureSchemeEnum.WINTERNITZ
        print("Winternitz Signature Scheme selected")
    
    print("Type help for a list of commands")

    global_params = make_params(signature_scheme=signature, batching=1, num_parties=3, threshold_k=2, num_leaves=2)
    party_ids = ["Bob", "Alice", "Aidan"]
    
    controller = SystemController(global_params, party_ids)
    
    cli = SystemControllerCLI(controller)
    cli.cmdloop()

if __name__ == '__main__':
    main()