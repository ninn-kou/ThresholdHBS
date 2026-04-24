## COMP6453-Team-Project


### Project Structure

```text
threshold_hbs/
├── abstractions/  
│   ├── _init_.py_               
│   ├── merkle_tree.py   
│   ├── singature_scheme.py   
├── extensions/           
├── signatures/ 
│   ├── lamport.py               
│   ├── winternitz.py            
├── winternitz/            
│   ├── src/               
│   ├── helpers.py         
│   └── winternitz.*       
├── models.py              
├── protocol.py            
├── sharing.py             
├── merkle.py              
├── peer_to_peer.py        
├── SystemController.py   
└── exceptions.py         
```

File Descriptions:  
- **SystemController.py**: High-level controller that manages batching, signing flow, and integration of the hypertree-style structure.structure
- **sharing.py**: Utility functions for the threshold hash-based signature scheme, for size estimation, derivation of keys, and XOR logic. 
- **protocol.py**: Provides utility functions for PRF-based share generation, XOR reconstruction, key encoding, signing and verification, as well as Extension 1 logic for coalition group generation and key assignment. It also implements batch signing and verification for Extension 3.
- **peer_to_peer.py**: Implements peer-to-peer coordination logic, including message proposals, approvals, and party interaction during the distributed signing workflow for Extension 2.
- **models.py**: Defines core data structures and dataclasses
- **merkle.py**: Implements Merkle tree construction, root computation, and authentication path generation and verification.
- **exceptions.py**: Defines custom exceptions for error handling, such as key reuse and signing failures.

- **helpers.py**: Provides helper functions for Winternitz one-time signatures, including key generation, signing, and verification.
- **lamport.py**: Defines the `LamportSignatureScheme` class, which implements the Lmaport one-time signature scheme with methods for keypair generation, signing, and verification
- **winternitz.py**: Defines the `WinternitzSignatureScheme` class, which implements the Winternitz one-time signature scheme with methods for keypair generation, signing and verification

- **merkle_tree.py**: Defines the `MerkleNode`, `MerkleTree`, `MerkleTreeSignatures`, and `MerkleTreeMessages` classes, providing utilities for Merkle tree construction, root digest computation, authentication path generation, and node hashing.
- **signature_scheme.py**: 

### Initial Demo & Testing

Run demo with:

```bash
python demo.py
```

Expected Output:

```
key_id: 0
randomizer_len: 8
auth_path_len: 3
lamport_values: 64
verified(original): True
verified(tampered): False
```

Run unit tests with:

```bash
python -m unittest discover -s tests -v
```

### Extensions

#### Extension 1: k-of-n via k-of-k subtrees

- `threshold_hbs/extensions/sharding.py`

Implement coalition-aware sharding first. Add a coalition list, map each `key_id` to exactly one coalition, and keep per-coalition usage counters so no two coalitions can reuse the same one-time key.

#### Extension 2: peer-to-peer message choice and signer choice

- `threshold_hbs/extensions/peer_to_peer.py`

Move message approval and signer selection out of the centralized aggregator path. Add a lightweight coordination layer where trustees approve the message and chosen coalition first, and let the untrusted server only return helper strings / CRV fragments.

#### Extension 3: Merkle batching at the leaves

- `threshold_hbs/extensions/batch_leaves.py`

Treat each leaf as a batch container rather than a single message slot. Build a small Merkle tree over buffered messages at the leaf, sign the batch root once, and attach both an inner batch proof and the outer authentication path during verification.

#### Extension 4: Merkle trees in higher layers

- `threshold_hbs/extensions/hybrid_merkle.py`

Generalize the current Merkle code so upper layers can be built from different node encodings while leaf behavior stays the same. Keep the current Lamport leaf verification untouched, then add a second layer of verification rules for higher-layer nodes.

#### Extension 5: Winternitz support

- `threshold_hbs/extensions/winternitz.py`

Add a new OTS module instead of modifying Lamport code directly. Implement Winternitz key generation, checksum handling, signing, and candidate-public-key reconstruction during verification, then let `protocol.py` choose between Lamport and Winternitz through a small adapter layer.
