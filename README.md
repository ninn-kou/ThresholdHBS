## COMP6453-Team-Project

### Part 0: Shared Data Classes

`SystemParameters`
`PartyBundle`
`DealerOutput`
`SignatureShare`
`ThresholdSignature`

### Part 1: Lamport core and hashing

This part owns the one-time signature primitive and nothing else. It can be built first and unit-tested independently.

Functions:
`hash_message`
`lamport_generate_keypair`
`lamport_sign`
`lamport_verify`

### Part 2: Merkle tree layer

This part commits all Lamport public keys under one public root and handles inclusion proofs.

Functions:
`build_merkle_tree`
`get_auth_path`
`verify_merkle_path`

### Part 3: Dealer setup and XOR sharing

This part is the offline setup layer. It depends on Part 1 and Part 2.

Functions:
`split_lamport_keypair_into_xor_shares`
`combine_signature_shares`
`dealer_setup`

### Part 4: Online signing, final verification, benchmark

This part is the full user-visible protocol layer. It depends on Parts 1-3.

Functions:
`party_sign_share`
`aggregator_sign`
`verify_threshold_signature`
`benchmark_minimal_prototype`
