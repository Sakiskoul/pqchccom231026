# Proof-Carrying Chains

Implementation accompanying the article *Proof-Carrying Chains for Transaction-Bound Signature
Authentication* (A. Koulianos, A. Litke, N. K. Papadakis).

A fixed group circuit verifies the signatures of an ordered group of transactions, a cyclic
accumulator folds the group proofs of a block into one block proof, and a cyclic chain step
verifies the previous chain proof together with the new block proof. The circuits use Plonky2
0.2.2 and a custom Poseidon-Winternitz signature relation. This is a research prototype. It does
not implement a standardised signature scheme and has not been audited.

## Build and test

The Rust toolchain is pinned in `rust-toolchain.toml`.

```sh
cargo build --release --locked
cargo test --release --locked --lib
```

Three recursive tests are ignored by default and can be run with
`cargo test --release --locked --lib -- --ignored --test-threads=1`.
The FRI query count is set with `PCB_FRI_QUERIES`. The article uses 76.

## Programs

| Program | Purpose |
|---|---|
| `group_cost` | Cost of the fixed group circuit at every occupancy |
| `fri_query_cost` | Group, block and chain cost for a given query count |
| `pcc_chain` | Chain construction and verification along a trajectory |
| `pcc_adversarial` | Binding, replay and circuit-family attack cases |
| `pcc_xmss` | XMSS-style many-time mode |
| `pcb_coordinator`, `pcb_worker` | Distributed proving runtime |
| `sched_bench` | Assignment policies, ablations and optimality gap |
| `pcb_binding_bench` | Cost of ordered commitment hashing |
| `pcb_adaptation_bench` | Persistent calibration of worker profiles |
| `pcb_history_bench`, `pcb_replay_bench` | Named-history authentication and native replay |
| `native_wots_verify` | Native signature verification |
| `hash_cost` | SHA-256 and Poseidon arithmetisation |
| `sota_group_cost` | Group proof for the same-host comparison |
| `pcb_fixture` | Message fixture for the external pipeline comparison |
| `pcb_check_artifacts` | Verification of persisted chain proofs against public histories |

`benchmarks/leanvm_e2e.rs` is the harness used for the leanVM pipeline comparison. It is built
inside a leanVM checkout at commit `98cb2ad4bdc5`.
