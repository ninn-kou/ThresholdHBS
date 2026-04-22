from tests.test_helpers import make_params
from threshold_hbs.SystemController import SystemController
from threshold_hbs.models import SystemParameters


params = make_params()
controller = SystemController(params, party_ids=["Alice", "Bob", "Charlie", "Dave", "Jimmy"])


controller.queue_message(b"Transfer $100 to Alice")
controller.queue_message(b"Approve Server Config X")
controller.queue_message(b"Deploy smart contract")


signatures = controller.sign_pending_batch()


for msg, sig in signatures:
    is_valid = controller.verify_message(msg, sig)
    print(f"Message {msg} valid: {is_valid}")