## COMP6453-Team-Project

### Project Introduction
This project investigates how stateful hash-based signatures can be adapted into thresh-
old and distributed signatures for post-quantum use. In a standard stateful hash-based
signature scheme, a signer prepares D one-time keys, authenticates their public keys with
a Merkle tree, and publishes the tree root as the composite public key. A signature can
be written as  
<p align="center">σ = (R, PATH, Z),</p>
where R is a randomizer, Z is the one-time signature, and PATH proves that the corre-
sponding one-time public key belongs to the published Merkle root. Since the scheme is
stateful, each one-time key, identified by a unique KeyID, must never be reused.
The aim of this project is not to design a new signature scheme, but to implement and
study the threshold construction described in the paper. In this model, a trusted dealer
generates the initial key material and a common reference value CRV , trustees hold shares
of the signing capability, and an untrusted aggregator coordinates the signing protocol and
combines trustee responses into a final signature. A key advantage of the construction
is that public verification remains the same as for the underlying stateful hash-based
signature scheme. The project begins with a Lamport–Merkle baseline and then considers
extensions such as k-of-n sharding, peer-to-peer coordination, more efficient Merkle-tree
organisation, batching, and Winternitz support. Because the total number of one-time
keys is limited, the allocation of KeyID values across coalitions is also an important
practical issue affecting both capacity and efficiency.

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

- **merkle_tree.py**: Defines the `MerkleNode`, `MerkleTree`, `MerkleTreeSignatures`, and `MerkleTreeMessages` classes, which provides utilities for Merkle tree construction, root digest computation, authentication path generation, and node hashing.
- **signature_scheme.py**: Defines the abstract `SignatureScheme`class, which provides shared hashing utilities and a common interface for keypair generation, signing and verification across schemes.   

###  Requirements

###  How to Run & Demo

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

### Test Coverage

# Implementation Details
### Base Project 
The project implements a threshold hash-based signature using one-time signatures and Merkle tree. Shares of signing materials are distibuted among all trustees at setup, and are then collaboratively combined when signing is requested by an aggregator. 

### Extension 1: k-of-n via k-of-k subtrees
Extension 1 introduces coalition-based signing. Each `key_id` is assigned to a coalition group of size `k`, so only the selected group participates in signing. This reduces the number of parties involved in each signing operation while preserving security through PRF-derived shares and CRV reconstruction.

### Extension 2: peer-to-peer message choice and signer choice
Extension 2 introduces the peer-to-peer coordination between trustees during the signing process, where parties can propose messages, approve requests and collaboratively participate in signing rather than relying solely on a central aggregator which could potentially be compromised. 

### Extension 3: Merkle batching at the leaves
Extension 3 reduces the cost of Lamport one-time keys by batching multiple messages into a small Merkle tree. A single Lamport key pair signs the batch root, allowing many messages to share one one-time key through inclusion proofs.

### Extension 4: Merkle trees in higher layers
Extension 4 addresses the scalability limitation of pre-generating all one-time key pairs during the initial system setup. Instead of constructing one large Merkle tree, the system generates a two-tiered structure consisting of an upper-layer tree and dynamically generated bottom-layer trees. Each bottom-tree root is signed by a single leaf in the upper tree, which significantly reduces the upfront key generation and distribute computational cost dynamically over the system lifetime.  

### Extension 5: Winternitz support
Extension 5 adds support for the Winternitz one-time signature scheme alongside Lamport signatures. It provides an alternative signing scheme with smaller signature sizes and configurable trade-offs between performance and efficiency, making it well suited for systems with high signing volume or limited storage and memory resources. 



