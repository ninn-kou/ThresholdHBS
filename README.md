## COMP6453-Team-Project

### Code Structures

- `threshold_hbs/lamport.py` for Lamport primitives
- `threshold_hbs/merkle.py` for Merkle tree logic
- `threshold_hbs/sharing.py` for XOR/PRF helpers
- `threshold_hbs/protocol.py` for dealer/trustee/aggregator logic
- `threshold_hbs/models.py` for dataclasses

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

Run automated benchmarks with:

```bash
python3 -m unittest automated_benchmarks.py -v
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
