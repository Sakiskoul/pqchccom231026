use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Instant;

use pcb_recursive::pcc::{
    block_id, build_block_circuit, build_chain_circuit, build_group_circuit,
    build_group_targets_with_id_pub, deployment_query_rounds, group_circuit_id, group_digest,
    make_block, prove_group, recursion_config,
    tip_hash, BlockCircuit, ChainCircuit, GroupCircuit, GroupMode, C, D, F, GPI_GROUP_BUDGET,
    GPI_GROUP_DIGEST, PCB_VERSION,
};
use plonky2::field::types::Field;
use plonky2::gates::noop::NoopGate;
use plonky2::hash::hash_types::HashOut;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::Hasher;
use plonky2::plonk::proof::ProofWithPublicInputs;

type Proof = ProofWithPublicInputs<F, C, D>;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Outcome {
    ProducerError,
    WitnessConflict,
    ProducerPanic,
    InstanceMismatch,
    VerifyRejected,
    ShapeMismatch,
    NotApplicable,
    Accepted,
}

impl Outcome {
    fn label(&self) -> &'static str {
        match self {
            Outcome::ProducerError => "producer-error",
            Outcome::WitnessConflict => "witness-conflict",
            Outcome::ProducerPanic => "unexpected-panic",
            Outcome::InstanceMismatch => "instance-mismatch",
            Outcome::VerifyRejected => "reject(verify)",
            Outcome::ShapeMismatch => "shape-mismatch",
            Outcome::NotApplicable => "not-applicable",
            Outcome::Accepted => "ACCEPTED",
        }
    }
}

fn attempt<T>(f: impl FnOnce() -> anyhow::Result<T>) -> Result<T, Outcome> {
    let outcome = catch_unwind(AssertUnwindSafe(f));
    match outcome {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(error)) => {
            eprintln!("producer error: {error}");
            Err(Outcome::ProducerError)
        }
        Err(payload) => {
            let message = payload.downcast_ref::<String>().map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied()).unwrap_or("unknown panic");
            eprintln!("producer panic: {message}");
            if message.contains("Partition containing")
                && message.contains("was set twice with different values") {
                Err(Outcome::WitnessConflict)
            } else {
                Err(Outcome::ProducerPanic)
            }
        }
    }
}

struct Harness {
    gc: GroupCircuit,
    gc_alt_same_id: GroupCircuit,
    gc_alt_foreign_id: GroupCircuit,
    gc_wrong_budget: GroupCircuit,
    bc: BlockCircuit,
    bc_alt_same_id: BlockCircuit,
    cc: ChainCircuit,
    genesis: HashOut<F>,
    k: usize,
    g: usize,
}

fn build_group_circuit_alt(k_max: usize, circuit_id: HashOut<F>) -> GroupCircuit {
    let mut b = CircuitBuilder::<F, D>::new(recursion_config(deployment_query_rounds()));
    let targets = build_group_targets_with_id_pub(&mut b, k_max, circuit_id);
    b.add_gate(NoopGate, vec![]);
    let data = b.build::<C>();
    GroupCircuit {
        data,
        targets,
        k_max,
        mode: GroupMode::Wots,
        circuit_id,
        query_rounds: deployment_query_rounds(),
    }
}

struct HonestBlock {
    bid: HashOut<F>,
    groups: Vec<Proof>,
    block_proof: Proof,
    tx_root: HashOut<F>,
    num_groups: u64,
    num_txs: u64,
}

fn honest_block(h: &Harness, height: u64, prev_hash: HashOut<F>, seed: u64) -> HonestBlock {
    let bb = make_block(seed, h.k, h.g);
    let bid = block_id(height, prev_hash, bb.tx_root);
    let mut groups = Vec::new();
    for (j, (txs, sigs)) in bb.groups.iter().zip(bb.sigs.iter()).enumerate() {
        let p = prove_group(&h.gc, bid, j as u64, txs, sigs).expect("honest group prove");
        h.gc.data.verify(p.clone()).expect("honest group verify");
        groups.push(p);
    }
    let mut bp = None;
    for gp in &groups {
        bp = Some(h.bc.step(bid, gp, bp.as_ref()).expect("honest accumulate"));
    }
    let block_proof = bp.unwrap();
    HonestBlock {
        bid,
        groups,
        block_proof,
        tx_root: bb.tx_root,
        num_groups: bb.groups.len() as u64,
        num_txs: bb.num_txs,
    }
}

fn judge_block(h: &Harness, outcome: Result<Proof, Outcome>) -> Outcome {
    match outcome {
        Err(o) => o,
        Ok(p) => {
            if h.bc.data.verify(p).is_ok() {
                Outcome::Accepted
            } else {
                Outcome::VerifyRejected
            }
        }
    }
}

fn judge_chain(h: &Harness, outcome: Result<Proof, Outcome>) -> Outcome {
    match outcome {
        Err(o) => o,
        Ok(p) => {
            if h.cc.verify_chain(&p, h.genesis).is_ok() {
                Outcome::Accepted
            } else {
                Outcome::VerifyRejected
            }
        }
    }
}

fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().collect();
    let g: usize = a.get(1).and_then(|s| s.parse().ok()).unwrap_or(2);
    let k: usize = a.get(2).and_then(|s| s.parse().ok()).unwrap_or(4);

    eprintln!("building circuits ...");
    let t = Instant::now();
    let gc = build_group_circuit(g);
    let allowed_id = group_circuit_id(g, GroupMode::Wots);
    let foreign_id = HashOut { elements: [F::from_canonical_u64(0xF04E_164E); 4] };
    let gc_alt_same_id = build_group_circuit_alt(g, allowed_id);
    let gc_alt_foreign_id = build_group_circuit_alt(g, foreign_id);
    let gc_wrong_budget = build_group_circuit(g + 1);
    let bc = build_block_circuit(&gc);
    let bc_alt_same_id = build_block_circuit(&gc_alt_same_id);
    let cc = build_chain_circuit(&bc, &gc);
    eprintln!("  built in {:.1}s", t.elapsed().as_secs_f64());
    assert_eq!(gc.data.common, gc_alt_same_id.data.common, "alt circuit must share the proof shape");
    assert_eq!(
        gc.data.common, gc_alt_foreign_id.data.common,
        "foreign-id circuit must share the proof shape"
    );
    assert_ne!(
        gc.data.verifier_only.circuit_digest, gc_alt_same_id.data.verifier_only.circuit_digest,
        "alt circuit must have a different verifier key"
    );
    assert_eq!(
        bc.data.common, bc_alt_same_id.data.common,
        "alt block circuit must share the proof shape"
    );
    assert_ne!(
        bc.data.verifier_only.circuit_digest,
        bc_alt_same_id.data.verifier_only.circuit_digest,
        "alt block circuit must have a different verifier key"
    );

    let genesis = HashOut { elements: [F::from_canonical_u64(0xACE0); 4] };
    let h = Harness {
        gc,
        gc_alt_same_id,
        gc_alt_foreign_id,
        gc_wrong_budget,
        bc,
        bc_alt_same_id,
        cc,
        genesis,
        k,
        g,
    };

    let b1 = honest_block(&h, 1, h.genesis, 11);
    let c1 = h.cc.step(h.genesis, 1, h.genesis, &b1.block_proof, None)?;
    let tip1 = tip_hash(b1.bid, b1.tx_root, b1.num_groups, b1.num_txs);
    let b2 = honest_block(&h, 2, tip1, 22);
    let c2 = h.cc.step(h.genesis, 2, tip1, &b2.block_proof, Some(&c1))?;
    let tip2 = tip_hash(b2.bid, b2.tx_root, b2.num_groups, b2.num_txs);
    let b3 = honest_block(&h, 3, tip2, 33);
    let c3 = h.cc.step(h.genesis, 3, tip2, &b3.block_proof, Some(&c2))?;
    let tip3 = tip_hash(b3.bid, b3.tx_root, b3.num_groups, b3.num_txs);

    let mut rows: Vec<(&str, &str, &str, Outcome, Outcome)> = Vec::new();
    let mut record = |layer: &'static str,
                      attack: &'static str,
                      bound: &'static str,
                      api: Outcome,
                      circuit: Outcome| {
        println!("{layer},{attack},{bound},{},{}", api.label(), circuit.label());
        rows.push((layer, attack, bound, api, circuit));
    };

    println!("layer,attack,binding mechanism,api outcome,circuit outcome");

    let control = if h.cc.verify_chain(&c3, h.genesis).is_ok() {
        Outcome::Accepted
    } else {
        Outcome::VerifyRejected
    };
    record(
        "chain",
        "honest block proof and honest previous chain proof",
        "none needed",
        control,
        control,
    );
    let control = if h
        .bc
        .verify_block(&b3.block_proof, b3.bid, b3.tx_root, b3.num_groups, b3.num_txs)
        .is_ok()
    {
        Outcome::Accepted
    } else {
        Outcome::VerifyRejected
    };
    record(
        "block",
        "honest aggregated block proof against its public data",
        "none needed",
        control,
        control,
    );
    {
        let bb = make_block(99, h.g + 1, h.g);
        let bid = block_id(1, h.genesis, bb.tx_root);
        let mut bp = None;
        for (j, (txs, sigs)) in bb.groups.iter().zip(bb.sigs.iter()).enumerate() {
            let gp = prove_group(&h.gc, bid, j as u64, txs, sigs)?;
            bp = Some(h.bc.step(bid, &gp, bp.as_ref())?);
        }
        let bp = bp.expect("mixed-occupancy block has groups");
        let control = if h
            .bc
            .verify_block(&bp, bid, bb.tx_root, bb.groups.len() as u64, bb.num_txs)
            .is_ok()
        {
            Outcome::Accepted
        } else {
            Outcome::VerifyRejected
        };
        record(
            "block",
            "honest mixed-occupancy plan under one fixed circuit",
            "constant group VK with padded occupancy",
            control,
            control,
        );
    }

    {
        let bb = make_block(101, h.k, h.g);
        let bid = block_id(1, h.genesis, bb.tx_root);
        let mut sigs = bb.sigs[0].clone();
        sigs[0][0] = HashOut { elements: [F::from_canonical_u64(7); 4] };
        let o = match attempt(|| prove_group(&h.gc, bid, 0, &bb.groups[0], &sigs)) {
            Err(outcome) => outcome,
            Ok(p) => {
                if h.gc.data.verify(p).is_ok() {
                    Outcome::Accepted
                } else {
                    Outcome::VerifyRejected
                }
            }
        };
        record("group", "forged WOTS signature", "in-circuit chain fold to the committed key", o, o);
    }
    {
        let bb = make_block(102, h.k, h.g);
        let mut txs = bb.groups[0].clone();
        txs[0].msg = HashOut { elements: [F::from_canonical_u64(0xBAD); 4] };
        let bid = block_id(1, h.genesis, bb.tx_root);
        let o = match attempt(|| prove_group(&h.gc, bid, 0, &txs, &bb.sigs[0])) {
            Err(outcome) => outcome,
            Ok(p) => {
                if h.gc.data.verify(p).is_ok() {
                    Outcome::Accepted
                } else {
                    Outcome::VerifyRejected
                }
            }
        };
        record("group", "tampered message", "in-circuit message-to-digit derivation", o, o);
    }
    {
        let bb = make_block(103, h.k, h.g);
        let bid = block_id(1, h.genesis, bb.tx_root);
        let p = prove_group(&h.gc, bid, 0, &bb.groups[0], &bb.sigs[0])?;
        let mut swapped = bb.groups[0].clone();
        if swapped.len() >= 2 {
            swapped.swap(0, 1);
        }
        let claimed = group_digest(&swapped, h.g);
        let actual = HashOut {
            elements: core::array::from_fn(|j| p.public_inputs[GPI_GROUP_DIGEST + j]),
        };
        let o = if claimed == actual { Outcome::Accepted } else { Outcome::InstanceMismatch };
        record("group", "reordered transactions within a group", "ordered group digest", o, o);
    }
    {
        let bb = make_block(106, h.g + 1, h.g);
        let txs: Vec<_> = bb.groups.iter().flatten().cloned().collect();
        let sigs: Vec<_> = bb.sigs.iter().flatten().cloned().collect();
        let bid = block_id(1, h.genesis, bb.tx_root);
        let o = if prove_group(&h.gc, bid, 0, &txs, &sigs).is_err() {
            Outcome::ProducerError
        } else {
            Outcome::Accepted
        };
        record(
            "group",
            "occupancy larger than the fixed circuit budget",
            "fixed number of circuit slots",
            o,
            Outcome::NotApplicable,
        );
    }
    {
        let bb = make_block(107, h.k, h.g);
        let bid = block_id(1, h.genesis, bb.tx_root);
        let mut proof = prove_group(&h.gc, bid, 0, &bb.groups[0], &bb.sigs[0])?;
        proof.public_inputs[GPI_GROUP_BUDGET] = F::from_canonical_u64((h.g + 1) as u64);
        let o = if h.gc.data.verify(proof).is_err() {
            Outcome::VerifyRejected
        } else {
            Outcome::Accepted
        };
        record(
            "group",
            "published group budget inconsistent with the circuit",
            "budget is a circuit constant and a proof public input",
            o,
            o,
        );
    }

    {
        let bb = make_block(104, h.k, h.g);
        let bid = block_id(9, h.genesis, bb.tx_root);
        let o = judge_block(&h, attempt(|| h.bc.step(bid, &b1.groups[0], None)));
        let c = judge_block(&h, attempt(|| h.bc.step_unchecked(bid, &b1.groups[0], None)));
        record("block", "group proof replayed from another block", "group block-id public input", o, c);
    }
    {
        let o = judge_block(&h, attempt(|| {
            let s1 = h.bc.step(b1.bid, &b1.groups[0], None)?;
            h.bc.step(b1.bid, &b1.groups[0], Some(&s1))
        }));
        let c = judge_block(&h, attempt(|| {
            let s1 = h.bc.step(b1.bid, &b1.groups[0], None)?;
            h.bc.step_unchecked(b1.bid, &b1.groups[0], Some(&s1))
        }));
        record("block", "duplicated group proof", "group index equals folded count", o, c);
    }
    if b1.groups.len() >= 2 {
        let o = judge_block(&h, attempt(|| h.bc.step(b1.bid, &b1.groups[1], None)));
        let c = judge_block(&h, attempt(|| h.bc.step_unchecked(b1.bid, &b1.groups[1], None)));
        record("block", "omitted group", "group index equals folded count", o, c);
        let o = judge_block(&h, attempt(|| {
            let s1 = h.bc.step(b1.bid, &b1.groups[1], None)?;
            h.bc.step(b1.bid, &b1.groups[0], Some(&s1))
        }));
        let c = judge_block(&h, attempt(|| {
            let s1 = h.bc.step_unchecked(b1.bid, &b1.groups[1], None)?;
            h.bc.step_unchecked(b1.bid, &b1.groups[0], Some(&s1))
        }));
        record("block", "reordered groups", "group index equals folded count", o, c);
    }
    {
        let bb = make_block(105, h.k, h.g);
        let bid = block_id(1, h.genesis, bb.tx_root);
        let alt = prove_group(&h.gc_alt_foreign_id, bid, 0, &bb.groups[0], &bb.sigs[0])?;
        assert!(
            h.gc_alt_foreign_id.data.verify(alt.clone()).is_ok(),
            "foreign proof must be valid for its own circuit"
        );
        assert!(h.gc.data.verify(alt.clone()).is_err(), "alt proof must not verify under gc");
        let o = judge_block(&h, attempt(|| h.bc.step(bid, &alt, None)));
        let c = judge_block(&h, attempt(|| h.bc.step_unchecked(bid, &alt, None)));
        record(
            "block",
            "valid group proof under a verification key outside the permitted set",
            "constant group VK and circuit identifier in the accumulator",
            o,
            c,
        );
    }
    {
        let bb = make_block(108, h.k, h.g);
        let bid = block_id(1, h.genesis, bb.tx_root);
        let alt = prove_group(&h.gc_alt_same_id, bid, 0, &bb.groups[0], &bb.sigs[0])?;
        assert!(h.gc_alt_same_id.data.verify(alt.clone()).is_ok());
        let o = judge_block(&h, attempt(|| h.bc.step(bid, &alt, None)));
        let c = judge_block(&h, attempt(|| h.bc.step_unchecked(bid, &alt, None)));
        record(
            "block",
            "outside verification key paired with the allowed circuit identifier",
            "constant group VK in the accumulator",
            o,
            c,
        );
    }
    {
        let bb = make_block(109, h.k, h.g + 1);
        let bid = block_id(1, h.genesis, bb.tx_root);
        let alt = prove_group(&h.gc_wrong_budget, bid, 0, &bb.groups[0], &bb.sigs[0])?;
        let o = judge_block(&h, attempt(|| h.bc.step(bid, &alt, None)));
        let c = if Proof::from_bytes(alt.to_bytes(), &h.gc.data.common).is_err() {
            Outcome::ShapeMismatch
        } else {
            judge_block(&h, attempt(|| h.bc.step_unchecked(bid, &alt, None)))
        };
        record(
            "block",
            "proof produced by a group circuit with another budget",
            "fixed proof shape and constant group VK",
            o,
            c,
        );
    }
    {
        let mut bytes = b1.block_proof.to_bytes();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xFF;
        let o = match Proof::from_bytes(bytes, &h.bc.data.common) {
            Err(_) => Outcome::VerifyRejected,
            Ok(p) => {
                if h.bc.data.verify(p).is_ok() {
                    Outcome::Accepted
                } else {
                    Outcome::VerifyRejected
                }
            }
        };
        record("block", "corrupted block-proof bytes", "FRI and Merkle commitments", o, Outcome::NotApplicable);
    }
    {
        let fake = HashOut { elements: [F::from_canonical_u64(0xF00D); 4] };
        let o = if h
            .bc
            .verify_block(&b1.block_proof, b1.bid, fake, b1.num_groups, b1.num_txs)
            .is_ok()
        {
            Outcome::Accepted
        } else {
            Outcome::VerifyRejected
        };
        record("block", "fabricated transaction commitment", "block public outputs", o, Outcome::NotApplicable);
    }

    {
        let b4 = honest_block(&h, 4, tip3, 44);
        let o = judge_chain(&h, attempt(|| h.cc.step(h.genesis, 5, tip3, &b4.block_proof, Some(&c3))));
        let c = judge_chain(&h, attempt(|| h.cc.step_unchecked(h.genesis, 5, tip3, &b4.block_proof, Some(&c3))));
        record("chain", "wrong block height", "height = previous height + 1", o, c);

        let bogus = HashOut { elements: [F::from_canonical_u64(0xDEAD); 4] };
        let o = judge_chain(&h, attempt(|| h.cc.step(h.genesis, 4, bogus, &b4.block_proof, Some(&c3))));
        let c = judge_chain(&h, attempt(|| h.cc.step_unchecked(h.genesis, 4, bogus, &b4.block_proof, Some(&c3))));
        record("chain", "wrong previous block hash", "prev hash = previous tip hash", o, c);

        let o = judge_chain(&h, attempt(|| h.cc.step(h.genesis, 4, tip3, &b4.block_proof, Some(&c2))));
        let c = judge_chain(&h, attempt(|| h.cc.step_unchecked(h.genesis, 4, tip3, &b4.block_proof, Some(&c2))));
        record("chain", "omitted block", "height and previous-tip continuity", o, c);
    }
    {
        let o = judge_chain(&h, attempt(|| h.cc.step(h.genesis, 4, tip3, &b2.block_proof, Some(&c3))));
        let c = judge_chain(&h, attempt(|| h.cc.step_unchecked(h.genesis, 4, tip3, &b2.block_proof, Some(&c3))));
        record("chain", "block proof replayed at another height", "block id binds height", o, c);
    }
    {
        let o = judge_chain(&h, attempt(|| h.cc.step(h.genesis, 2, tip1, &b3.block_proof, Some(&c1))));
        let c = judge_chain(&h, attempt(|| h.cc.step_unchecked(h.genesis, 2, tip1, &b3.block_proof, Some(&c1))));
        record("chain", "reordered blocks", "block id binds height and previous hash", o, c);
    }
    {
        let bb = make_block(55, h.k, h.g);
        let lying_root = HashOut { elements: [F::from_canonical_u64(0x1234); 4] };
        let bid = block_id(4, tip3, lying_root);
        let mut gps = Vec::new();
        for (j, (txs, sigs)) in bb.groups.iter().zip(bb.sigs.iter()).enumerate() {
            gps.push(prove_group(&h.gc, bid, j as u64, txs, sigs)?);
        }
        let mut bp = None;
        for gp in &gps {
            bp = Some(h.bc.step(bid, gp, bp.as_ref())?);
        }
        let bp = bp.unwrap();
        let o = judge_chain(&h, attempt(|| h.cc.step(h.genesis, 4, tip3, &bp, Some(&c3))));
        let c = judge_chain(&h, attempt(|| h.cc.step_unchecked(h.genesis, 4, tip3, &bp, Some(&c3))));
        record(
            "chain",
            "block proof for a different transaction root",
            "block id binds the aggregate's own commitment",
            o,
            c,
        );
    }
    {
        let bb = make_block(66, h.k, h.g);
        let mut v = vec![
            F::from_canonical_u64(0x5043_4200_424C_4B00),
            F::from_canonical_u64(4),
        ];
        v.extend_from_slice(&tip3.elements);
        v.extend_from_slice(&bb.tx_root.elements);
        v.push(F::from_canonical_u64(PCB_VERSION + 1));
        let bid = PoseidonHash::hash_no_pad(&v);
        let mut gps = Vec::new();
        for (j, (txs, sigs)) in bb.groups.iter().zip(bb.sigs.iter()).enumerate() {
            gps.push(prove_group(&h.gc, bid, j as u64, txs, sigs)?);
        }
        let mut bp = None;
        for gp in &gps {
            bp = Some(h.bc.step(bid, gp, bp.as_ref())?);
        }
        let bp = bp.unwrap();
        let o = judge_chain(&h, attempt(|| h.cc.step(h.genesis, 4, tip3, &bp, Some(&c3))));
        let c = judge_chain(&h, attempt(|| h.cc.step_unchecked(h.genesis, 4, tip3, &bp, Some(&c3))));
        record("chain", "circuit-version substitution", "version inside the block id", o, c);
    }
    {
        let mut bytes = c3.to_bytes();
        let mid = bytes.len() / 3;
        bytes[mid] ^= 0xFF;
        let o = match Proof::from_bytes(bytes, &h.cc.data.common) {
            Err(_) => Outcome::VerifyRejected,
            Ok(p) => {
                if h.cc.verify_chain(&p, h.genesis).is_ok() {
                    Outcome::Accepted
                } else {
                    Outcome::VerifyRejected
                }
            }
        };
        record("chain", "corrupted chain-proof bytes", "FRI and Merkle commitments", o, Outcome::NotApplicable);
    }
    {
        let other = HashOut { elements: [F::from_canonical_u64(1); 4] };
        let o = if h.cc.verify_chain(&c3, other).is_ok() {
            Outcome::Accepted
        } else {
            Outcome::VerifyRejected
        };
        record("chain", "wrong genesis commitment", "genesis carried as a public input", o, Outcome::NotApplicable);
    }
    {
        let bb = make_block(77, h.k, h.g);
        let bid = block_id(4, tip3, bb.tx_root);
        let mut alt_block = None;
        for (j, (txs, sigs)) in bb.groups.iter().zip(&bb.sigs).enumerate() {
            let gp = prove_group(&h.gc_alt_same_id, bid, j as u64, txs, sigs)?;
            alt_block = Some(h.bc_alt_same_id.step(bid, &gp, alt_block.as_ref())?);
        }
        let alt_block = alt_block.expect("foreign block has groups");
        assert!(
            h.bc_alt_same_id
                .verify_block(
                    &alt_block,
                    bid,
                    bb.tx_root,
                    bb.groups.len() as u64,
                    bb.num_txs,
                )
                .is_ok(),
            "foreign block proof must verify under its own key"
        );
        let o = judge_chain(&h, attempt(|| h.cc.step(h.genesis, 4, tip3, &alt_block, Some(&c3))));
        let c = judge_chain(&h, attempt(|| h.cc.step_unchecked(h.genesis, 4, tip3, &alt_block, Some(&c3))));
        record(
            "chain",
            "valid block proof under a shape-compatible foreign verification key",
            "constant block verification key in the chain step",
            o,
            c,
        );
    }

    let accepted = rows
        .iter()
        .filter(|(_, a, _, api, circuit)| {
            !a.starts_with("honest")
                && (*api == Outcome::Accepted || *circuit == Outcome::Accepted)
        })
        .count();
    let controls = rows
        .iter()
        .filter(|(_, a, _, api, circuit)| {
            a.starts_with("honest") && *api == Outcome::Accepted && *circuit == Outcome::Accepted
        })
        .count();
    eprintln!(
        "\n{} attacks, {} accepted (must be 0); {} honest controls accepted (must be 3)",
        rows.len() - 3,
        accepted,
        controls
    );
    anyhow::ensure!(accepted == 0, "a soundness attack succeeded");
    anyhow::ensure!(
        rows.iter().all(|(_, _, _, api, circuit)| {
            *api != Outcome::ProducerPanic && *circuit != Outcome::ProducerPanic
        }),
        "an unexpected producer panic requires investigation"
    );
    anyhow::ensure!(controls == 3, "an honest control was rejected");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn producer_outcomes_remain_distinct() {
        assert_eq!(attempt(|| Ok(7)), Ok(7));
        assert_eq!(attempt::<()>(|| anyhow::bail!("input validation")), Err(Outcome::ProducerError));
        assert_eq!(attempt::<()>(|| panic!("unexpected failure")), Err(Outcome::ProducerPanic));
        assert_eq!(
            attempt::<()>(|| panic!("Partition containing target was set twice with different values")),
            Err(Outcome::WitnessConflict)
        );
    }
}
