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

## Reported values

`data/` holds the per-run records of the reported campaigns. `scripts/tables.py` recomputes the
values reported in the article from these records, and `scripts/test_tables.py` checks them
against the published numbers. Python 3.9 or newer with the standard library is sufficient.

```sh
python scripts/tables.py            # every section
python scripts/tables.py budget     # one section
python -m unittest discover -s scripts
```

## Measurements

Unless stated otherwise, runs use `PCB_FRI_QUERIES=76`, Linux, release builds and one physical core
per worker (`taskset`). Executables are in `target/release`.

| Result | Command | Data |
|---|---|---|
| Table 1, query cost | `fri_query_cost Q 5 4 128 4` for Q = 28, 56, 76, 95 | `query_cost/` |
| Table 3, occupancy cost | `group_cost 4 1,2,3,4 5` | `cost_model/` |
| Table 4, chain | `pcc_chain 128 8 4 5`, and `pcc_chain 8 16 4 5` for the larger block | `chain/` |
| Table 5, attack cases | `pcc_adversarial 4 8` and `pcc_xmss 5,10 4 8 4 5` | `adversarial/`, `xmss/` |
| Tables 6 and 7, assignment model | `sched_bench OUT data/cost_model/group_cost.csv 4` | `scheduling/` |
| Table 8, fault and network results | `pcb_coordinator --k 32 --g 4 --workers W --scheduler resource --mem 4096 --cost-model P --worker-profiles P --seed S` | `distributed/` |
| Aggregation figure | the same with `--k K --workers W --block-fan-in F` | `aggregation/` |
| Figure 4(a), wide area | coordinator with `--workers 4 --spawn-workers 2` and two `pcb_worker` processes on the remote host | `wide_area/` |
| Table 10, two hosts | coordinator with `--workers 8 --spawn-workers 4` and `pcb_worker HOST:PORT ID 4 4096 none 1 CORE` on the second host | `two_host/` |
| Table 12, same-host group proofs | `PCB_FRI_QUERIES=28 sota_group_cost N 5 28` for N = 1, 2, 4, 8, 16 | `external/same_host_runs.csv` |

`P` is `data/distributed/worker_profile_wW_g4.csv`. Worker profiles come from running
`group_cost 4 1,2,3,4 5` concurrently on each pinned core and merging the outputs with
`scripts/merge_group_profiles.py`.

**Table 9, group budget.** Two physical cores (`taskset -c 6,8`), a 16 GiB memory limit and
`RAYON_NUM_THREADS=2`. A height-one anchor is proved first, then each trial extends it.

```sh
pcb_coordinator --k 8 --g G --workers 2 --spawn-workers 2 --mem 4096 --scheduler maxfit \
  --cost-model data/budget/profile_gG.csv --worker-profiles data/budget/profile_gG.csv,data/budget/profile_gG.csv \
  --seed 202609234000 --chain-out anchor.proof --chain-height 1
pcb_coordinator --k K --g G --workers 2 --spawn-workers 2 --mem 4096 --scheduler maxfit \
  --cost-model data/budget/profile_gG.csv --worker-profiles data/budget/profile_gG.csv,data/budget/profile_gG.csv \
  --seed 202609235000+100K+REP --e2e-csv e2e.csv --summary-csv blocks.csv \
  --chain-in anchor.proof --chain-out chain.proof --chain-height 2
```

**Table 11, history authentication.** The inputs are the persisted histories and proofs.

```sh
RAYON_NUM_THREADS=2 taskset -c 6,8 pcb_replay_bench data/replay/inputs replay.csv 30
```

**Table 13, complete pipelines.** The PCB run is the Table 9 command at `G=4` with
`--mem 2048` and `data/external/profile.csv`. The leanVM run uses the same messages.

```sh
pcb_fixture K SEED messages.bin
RUST_MIN_STACK=536870912 pcb_e2e K SEED 1 OUT 0 messages.bin
```

`benchmarks/leanvm_e2e.rs` is the `pcb_e2e` harness. It is built as a binary inside a leanVM
checkout at commit `98cb2ad4bdc5`.
