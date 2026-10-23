use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use plonky2::field::extension::Extendable;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::gates::constant::ConstantGate;
use plonky2::gates::gate::GateRef;
use plonky2::gates::noop::NoopGate;
use plonky2::hash::hash_types::{HashOut, HashOutTarget, RichField};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget,
};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, Hasher, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
use plonky2::recursion::dummy_circuit::cyclic_base_proof;

use crate::wots_poseidon::{self, W, WM1};

pub type F = GoldilocksField;
pub const D: usize = 2;
pub type C = PoseidonGoldilocksConfig;

pub const PCB_VERSION: u64 = 4;

pub const MAX_CHAIN_BLOCKS: u64 = 1 << 20;
pub const MAX_BLOCK_GROUPS: u64 = 1 << 8;

const DOM_MSG_DIGITS: u64 = 0x5043_4200_4D53_4700;
const DOM_TX_LEAF: u64 = 0x5043_4200_5458_0000;
const DOM_GROUP: u64 = 0x5043_4200_4752_5000;
const DOM_ACC: u64 = 0x5043_4200_4143_4300;
const DOM_BLOCK_ID: u64 = 0x5043_4200_424C_4B00;
const DOM_TIP: u64 = 0x5043_4200_5449_5000;
const DOM_CHAIN: u64 = 0x5043_4200_4348_4E00;
const DOM_VK: u64 = 0x5043_4200_564B_0000;
const DOM_GROUP_CIRCUIT: u64 = 0x5043_4200_4743_4900;
const DOM_NULL_LEAF: u64 = 0x5043_4200_4E55_4C00;
const DOM_XMSS_LEAF: u64 = 0x5043_4200_584D_5300;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupMode {
    Wots,
    Xmss { height: usize },
}

impl GroupMode {
    pub fn tag(&self) -> String {
        match self {
            GroupMode::Wots => "wots".into(),
            GroupMode::Xmss { height } => format!("xmss-h{height}"),
        }
    }
}

pub const DEFAULT_FRI_QUERY_ROUNDS: usize = 28;

pub fn deployment_query_rounds() -> usize {
    static ROUNDS: OnceLock<usize> = OnceLock::new();
    *ROUNDS.get_or_init(|| match std::env::var("PCB_FRI_QUERIES") {
        Ok(raw) => {
            let rounds: usize = raw
                .trim()
                .parse()
                .unwrap_or_else(|_| panic!("PCB_FRI_QUERIES must be a positive integer, got {raw:?}"));
            assert!(rounds > 0, "PCB_FRI_QUERIES must be positive");
            rounds
        }
        Err(_) => DEFAULT_FRI_QUERY_ROUNDS,
    })
}

pub fn recursion_config(query_rounds: usize) -> CircuitConfig {
    let mut config = CircuitConfig::standard_recursion_config();
    config.fri_config.num_query_rounds = query_rounds;
    config
}

pub fn group_circuit_id(k_max: usize, mode: GroupMode) -> HashOut<F> {
    group_circuit_id_with_queries(k_max, mode, deployment_query_rounds())
}

pub fn group_circuit_id_with_queries(
    k_max: usize,
    mode: GroupMode,
    query_rounds: usize,
) -> HashOut<F> {
    let (mode_tag, height) = match mode {
        GroupMode::Wots => (0u64, 0u64),
        GroupMode::Xmss { height } => (1u64, height as u64),
    };
    PoseidonHash::hash_no_pad(&[
        dom(DOM_GROUP_CIRCUIT),
        F::from_canonical_u64(PCB_VERSION),
        F::from_canonical_u64(k_max as u64),
        F::from_canonical_u64(mode_tag),
        F::from_canonical_u64(height),
        F::from_canonical_u64(query_rounds as u64),
    ])
}

pub const N_MSG_DIGITS: usize = 64;
pub const N_CSUM_DIGITS: usize = 3;
pub const L: usize = N_MSG_DIGITS + N_CSUM_DIGITS;

fn dom(x: u64) -> F {
    F::from_canonical_u64(x)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tx {
    pub pk: HashOut<F>,
    pub msg: HashOut<F>,
    pub index: u64,
}

pub fn digits_of(msg: HashOut<F>) -> Vec<usize> {
    let mut pre = vec![dom(DOM_MSG_DIGITS)];
    pre.extend_from_slice(&msg.elements);
    let hdr = PoseidonHash::hash_no_pad(&pre);
    let mut d = Vec::with_capacity(L);
    for e in hdr.elements {
        let mut x = e.to_canonical_u64();
        for _ in 0..16 {
            d.push((x & 0xF) as usize);
            x >>= 4;
        }
    }
    debug_assert_eq!(d.len(), N_MSG_DIGITS);
    let csum: usize = d.iter().map(|&x| WM1 - x).sum();
    let mut c = csum;
    for _ in 0..N_CSUM_DIGITS {
        d.push(c % W);
        c /= W;
    }
    debug_assert_eq!(c, 0, "checksum must fit in {N_CSUM_DIGITS} base-{W} digits");
    d
}

pub fn tx_leaf(tx: &Tx) -> HashOut<F> {
    let mut v = vec![dom(DOM_TX_LEAF)];
    v.extend_from_slice(&tx.pk.elements);
    v.extend_from_slice(&tx.msg.elements);
    PoseidonHash::hash_no_pad(&v)
}

pub fn xmss_tx_leaf(tx: &Tx) -> HashOut<F> {
    let mut v = vec![dom(DOM_XMSS_LEAF)];
    v.extend_from_slice(&tx.pk.elements);
    v.extend_from_slice(&tx.msg.elements);
    v.push(F::from_canonical_u64(tx.index));
    PoseidonHash::hash_no_pad(&v)
}

pub fn leaf_of(tx: &Tx, mode: GroupMode) -> HashOut<F> {
    match mode {
        GroupMode::Wots => tx_leaf(tx),
        GroupMode::Xmss { .. } => xmss_tx_leaf(tx),
    }
}

fn null_leaf() -> HashOut<F> {
    PoseidonHash::hash_no_pad(&[dom(DOM_NULL_LEAF)])
}

pub fn group_digest_mode(txs: &[Tx], k_max: usize, mode: GroupMode) -> HashOut<F> {
    assert!(txs.len() <= k_max, "group larger than the circuit budget");
    let mut v = vec![dom(DOM_GROUP)];
    for i in 0..k_max {
        let leaf = if i < txs.len() { leaf_of(&txs[i], mode) } else { null_leaf() };
        v.extend_from_slice(&leaf.elements);
    }
    PoseidonHash::hash_no_pad(&v)
}

pub fn group_digest(txs: &[Tx], k_max: usize) -> HashOut<F> {
    group_digest_mode(txs, k_max, GroupMode::Wots)
}

pub fn fold_acc(acc: HashOut<F>, gd: HashOut<F>) -> HashOut<F> {
    let mut v = vec![dom(DOM_ACC)];
    v.extend_from_slice(&acc.elements);
    v.extend_from_slice(&gd.elements);
    PoseidonHash::hash_no_pad(&v)
}

pub fn zero_hash() -> HashOut<F> {
    HashOut { elements: [F::ZERO; 4] }
}

pub fn tx_root_mode(groups: &[Vec<Tx>], k_max: usize, mode: GroupMode) -> HashOut<F> {
    let mut acc = zero_hash();
    for g in groups {
        acc = fold_acc(acc, group_digest_mode(g, k_max, mode));
    }
    acc
}

pub fn tx_root(groups: &[Vec<Tx>], k_max: usize) -> HashOut<F> {
    tx_root_mode(groups, k_max, GroupMode::Wots)
}

pub fn block_id(height: u64, prev_hash: HashOut<F>, tx_root: HashOut<F>) -> HashOut<F> {
    let mut v = vec![dom(DOM_BLOCK_ID), F::from_canonical_u64(height)];
    v.extend_from_slice(&prev_hash.elements);
    v.extend_from_slice(&tx_root.elements);
    v.push(F::from_canonical_u64(PCB_VERSION));
    PoseidonHash::hash_no_pad(&v)
}

pub fn tip_hash(bid: HashOut<F>, acc: HashOut<F>, num_groups: u64, num_txs: u64) -> HashOut<F> {
    let mut v = vec![dom(DOM_TIP)];
    v.extend_from_slice(&bid.elements);
    v.extend_from_slice(&acc.elements);
    v.push(F::from_canonical_u64(num_groups));
    v.push(F::from_canonical_u64(num_txs));
    PoseidonHash::hash_no_pad(&v)
}

pub fn fold_chain(prev: HashOut<F>, tip: HashOut<F>) -> HashOut<F> {
    let mut v = vec![dom(DOM_CHAIN)];
    v.extend_from_slice(&prev.elements);
    v.extend_from_slice(&tip.elements);
    PoseidonHash::hash_no_pad(&v)
}

pub fn native_verify(tx: &Tx, sigma: &[HashOut<F>]) -> bool {
    let d = digits_of(tx.msg);
    wots_poseidon::verify(tx.pk, &d, sigma)
}

fn hash_targets(b: &mut CircuitBuilder<F, D>, v: Vec<Target>) -> HashOutTarget {
    b.hash_n_to_hash_no_pad::<PoseidonHash>(v)
}

fn select_hash(
    b: &mut CircuitBuilder<F, D>,
    cond: BoolTarget,
    t: HashOutTarget,
    f: HashOutTarget,
) -> HashOutTarget {
    HashOutTarget { elements: core::array::from_fn(|j| b.select(cond, t.elements[j], f.elements[j])) }
}

fn canonical_bits_64(b: &mut CircuitBuilder<F, D>, x: Target) -> Vec<BoolTarget> {
    let bits = b.split_le(x, 64);
    let mut all_high = b.one();
    for bit in bits.iter().take(64).skip(32) {
        all_high = b.mul(all_high, bit.target);
    }
    let mut all_low_zero = b.one();
    for bit in bits.iter().take(32) {
        let nb = b.not(*bit);
        all_low_zero = b.mul(all_low_zero, nb.target);
    }
    let one = b.one();
    let low_nonzero = b.sub(one, all_low_zero);
    let bad = b.mul(all_high, low_nonzero);
    let zero = b.zero();
    b.connect(bad, zero);
    bits
}

fn derive_digits_target(b: &mut CircuitBuilder<F, D>, msg: HashOutTarget) -> Vec<Target> {
    let mut pre = vec![b.constant(dom(DOM_MSG_DIGITS))];
    pre.extend_from_slice(&msg.elements);
    let hdr = hash_targets(b, pre);

    let mut digits: Vec<Target> = Vec::with_capacity(L);
    for j in 0..4 {
        let bits = canonical_bits_64(b, hdr.elements[j]);
        for n in 0..16 {
            let mut acc = bits[4 * n].target;
            for k in 1..4 {
                let w = b.constant(F::from_canonical_u64(1u64 << k));
                acc = b.mul_add(bits[4 * n + k].target, w, acc);
            }
            digits.push(acc);
        }
    }
    debug_assert_eq!(digits.len(), N_MSG_DIGITS);

    let wm1c = b.constant(F::from_canonical_u64(WM1 as u64));
    let mut csum = b.zero();
    for &d in digits.iter().take(N_MSG_DIGITS) {
        let t = b.sub(wm1c, d);
        csum = b.add(csum, t);
    }
    let bits = b.split_le(csum, 4 * N_CSUM_DIGITS);
    for j in 0..N_CSUM_DIGITS {
        let mut acc = bits[4 * j].target;
        for k in 1..4 {
            let w = b.constant(F::from_canonical_u64(1u64 << k));
            acc = b.mul_add(bits[4 * j + k].target, w, acc);
        }
        digits.push(acc);
    }
    digits
}

fn chain_end_target(b: &mut CircuitBuilder<F, D>, sigma: HashOutTarget, d: Target) -> HashOutTarget {
    let mut hs: Vec<HashOutTarget> = Vec::with_capacity(W);
    hs.push(sigma);
    for k in 1..=WM1 {
        let prev = hs[k - 1];
        let next = hash_targets(b, prev.elements.to_vec());
        hs.push(next);
    }
    b.range_check(d, 4);
    let wm1 = b.constant(F::from_canonical_u64(WM1 as u64));
    let idx = b.sub(wm1, d);
    let mut out = [b.zero(); 4];
    for (j, o) in out.iter_mut().enumerate() {
        let column: Vec<Target> = hs.iter().map(|hh| hh.elements[j]).collect();
        *o = b.random_access(idx, column);
    }
    HashOutTarget { elements: out }
}

pub const GPI_BLOCK_ID: usize = 0;
pub const GPI_GROUP_INDEX: usize = 4;
pub const GPI_CIRCUIT_ID: usize = 5;
pub const GPI_GROUP_BUDGET: usize = 9;
pub const GPI_GROUP_DIGEST: usize = 10;
pub const GPI_TX_COUNT: usize = 14;
pub const GROUP_NUM_PI: usize = 15;

pub struct GroupTargets {
    pub block_id: HashOutTarget,
    pub group_index: Target,
    pub circuit_id: HashOutTarget,
    pub group_budget: Target,
    pub group_digest: HashOutTarget,
    pub tx_count: Target,
    pub live: Vec<BoolTarget>,
    pub msgs: Vec<HashOutTarget>,
    pub sigmas: Vec<Vec<HashOutTarget>>,
    pub roots: Vec<HashOutTarget>,
    pub paths: Vec<Vec<HashOutTarget>>,
    pub index_bits: Vec<Vec<BoolTarget>>,
    pub mode: GroupMode,
}

pub struct GroupCircuit {
    pub data: CircuitData<F, C, D>,
    pub targets: GroupTargets,
    pub k_max: usize,
    pub mode: GroupMode,
    pub circuit_id: HashOut<F>,
    pub query_rounds: usize,
}

fn build_group_targets(b: &mut CircuitBuilder<F, D>, k_max: usize) -> GroupTargets {
    build_group_targets_mode(b, k_max, GroupMode::Wots)
}

fn build_group_targets_mode(
    b: &mut CircuitBuilder<F, D>,
    k_max: usize,
    mode: GroupMode,
) -> GroupTargets {
    build_group_targets_mode_with_id(b, k_max, mode, group_circuit_id(k_max, mode))
}

fn build_group_targets_mode_with_id(
    b: &mut CircuitBuilder<F, D>,
    k_max: usize,
    mode: GroupMode,
    cid: HashOut<F>,
) -> GroupTargets {
    let block_id = b.add_virtual_hash();
    b.register_public_inputs(&block_id.elements);
    let group_index = b.add_virtual_public_input();
    let circuit_id = HashOutTarget {
        elements: core::array::from_fn(|j| b.constant(cid.elements[j])),
    };
    b.register_public_inputs(&circuit_id.elements);
    let group_budget = b.constant(F::from_canonical_u64(k_max as u64));
    b.register_public_input(group_budget);
    let group_digest = b.add_virtual_hash();
    b.register_public_inputs(&group_digest.elements);
    let tx_count = b.add_virtual_public_input();

    let null = {
        let c = b.constant(dom(DOM_NULL_LEAF));
        hash_targets(b, vec![c])
    };

    let mut live = Vec::with_capacity(k_max);
    let mut msgs = Vec::with_capacity(k_max);
    let mut sigmas = Vec::with_capacity(k_max);
    let mut roots = Vec::with_capacity(k_max);
    let mut paths = Vec::with_capacity(k_max);
    let mut index_bits = Vec::with_capacity(k_max);
    let mut leaves: Vec<Target> = vec![b.constant(dom(DOM_GROUP))];
    let mut count = b.zero();
    let mut prev_live: Option<BoolTarget> = None;

    for _ in 0..k_max {
        let lv = b.add_virtual_bool_target_safe();
        if let Some(pl) = prev_live {
            let npl = b.not(pl);
            let bad = b.mul(lv.target, npl.target);
            let zero = b.zero();
            b.connect(bad, zero);
        }
        prev_live = Some(lv);
        count = b.add(count, lv.target);

        let msg = b.add_virtual_hash();
        let digits = derive_digits_target(b, msg);
        let mut sig = Vec::with_capacity(L);
        let mut ends: Vec<Target> = Vec::with_capacity(L * 4);
        for d in digits.iter().take(L) {
            let s = b.add_virtual_hash();
            let e = chain_end_target(b, s, *d);
            ends.extend_from_slice(&e.elements);
            sig.push(s);
        }
        let pk = hash_targets(b, ends);

        let leaf = match mode {
            GroupMode::Wots => {
                let mut leaf_in = vec![b.constant(dom(DOM_TX_LEAF))];
                leaf_in.extend_from_slice(&pk.elements);
                leaf_in.extend_from_slice(&msg.elements);
                roots.push(pk);
                paths.push(Vec::new());
                index_bits.push(Vec::new());
                hash_targets(b, leaf_in)
            }
            GroupMode::Xmss { height } => {
                let root = b.add_virtual_hash();
                let mut node = pk;
                let mut bits = Vec::with_capacity(height);
                let mut path = Vec::with_capacity(height);
                let mut index = b.zero();
                for level in 0..height {
                    let bit = b.add_virtual_bool_target_safe();
                    let sib = b.add_virtual_hash();
                    let mut inp = Vec::with_capacity(8);
                    let mut left = [b.zero(); 4];
                    let mut right = [b.zero(); 4];
                    for j in 0..4 {
                        left[j] = b.select(bit, sib.elements[j], node.elements[j]);
                        right[j] = b.select(bit, node.elements[j], sib.elements[j]);
                    }
                    inp.extend_from_slice(&left);
                    inp.extend_from_slice(&right);
                    node = hash_targets(b, inp);
                    let w = b.constant(F::from_canonical_u64(1u64 << level));
                    index = b.mul_add(bit.target, w, index);
                    bits.push(bit);
                    path.push(sib);
                }
                b.connect_hashes(node, root);
                let mut leaf_in = vec![b.constant(dom(DOM_XMSS_LEAF))];
                leaf_in.extend_from_slice(&root.elements);
                leaf_in.extend_from_slice(&msg.elements);
                leaf_in.push(index);
                roots.push(root);
                paths.push(path);
                index_bits.push(bits);
                hash_targets(b, leaf_in)
            }
        };
        let chosen = select_hash(b, lv, leaf, null);
        leaves.extend_from_slice(&chosen.elements);

        live.push(lv);
        msgs.push(msg);
        sigmas.push(sig);
    }

    let gd = hash_targets(b, leaves);
    b.connect_hashes(gd, group_digest);
    b.connect(count, tx_count);

    GroupTargets {
        block_id,
        group_index,
        circuit_id,
        group_budget,
        group_digest,
        tx_count,
        live,
        msgs,
        sigmas,
        roots,
        paths,
        index_bits,
        mode,
    }
}

pub fn build_group_targets_pub(b: &mut CircuitBuilder<F, D>, k_max: usize) -> GroupTargets {
    build_group_targets(b, k_max)
}

pub fn build_group_targets_with_id_pub(
    b: &mut CircuitBuilder<F, D>,
    k_max: usize,
    circuit_id: HashOut<F>,
) -> GroupTargets {
    build_group_targets_mode_with_id(b, k_max, GroupMode::Wots, circuit_id)
}

pub fn build_group_circuit(k_max: usize) -> GroupCircuit {
    build_group_circuit_with_queries(k_max, deployment_query_rounds())
}

pub fn build_group_circuit_with_queries(k_max: usize, query_rounds: usize) -> GroupCircuit {
    build_group_circuit_mode_with_queries(k_max, GroupMode::Wots, query_rounds)
}

pub fn build_group_circuit_mode(k_max: usize, mode: GroupMode) -> GroupCircuit {
    build_group_circuit_mode_with_queries(k_max, mode, deployment_query_rounds())
}

pub fn build_group_circuit_mode_with_queries(
    k_max: usize,
    mode: GroupMode,
    query_rounds: usize,
) -> GroupCircuit {
    assert!(k_max > 0, "group budget must be positive");
    if let GroupMode::Xmss { height } = mode {
        assert!(
            height < u64::BITS as usize,
            "XMSS tree height exceeds the public index width"
        );
    }
    let config = recursion_config(query_rounds);
    let circuit_id = group_circuit_id_with_queries(k_max, mode, query_rounds);
    let mut b = CircuitBuilder::<F, D>::new(config);
    let targets = build_group_targets_mode_with_id(&mut b, k_max, mode, circuit_id);
    let data = b.build::<C>();
    GroupCircuit { data, targets, k_max, mode, circuit_id, query_rounds }
}

pub fn prove_group(
    gc: &GroupCircuit,
    bid: HashOut<F>,
    group_index: u64,
    txs: &[Tx],
    sigmas: &[Vec<HashOut<F>>],
) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    prove_group_full(gc, bid, group_index, txs, sigmas, &[])
}

pub fn prove_group_full(
    gc: &GroupCircuit,
    bid: HashOut<F>,
    group_index: u64,
    txs: &[Tx],
    sigmas: &[Vec<HashOut<F>>],
    paths: &[Vec<HashOut<F>>],
) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    anyhow::ensure!(
        txs.len() == sigmas.len(),
        "one signature is required per transaction"
    );
    anyhow::ensure!(
        txs.len() <= gc.k_max,
        "occupancy exceeds the fixed group budget"
    );
    anyhow::ensure!(
        !txs.is_empty(),
        "empty groups are not valid block statements"
    );
    anyhow::ensure!(
        sigmas.iter().all(|signature| signature.len() == L),
        "every WOTS signature must contain exactly {L} chain values"
    );
    if let GroupMode::Xmss { height } = gc.mode {
        anyhow::ensure!(
            paths.len() == txs.len(),
            "one XMSS authentication path is required per transaction"
        );
        anyhow::ensure!(
            paths.iter().all(|path| path.len() == height),
            "every XMSS authentication path must match the circuit height"
        );
        let capacity = 1u64 << height;
        anyhow::ensure!(
            txs.iter().all(|tx| tx.index < capacity),
            "XMSS leaf index exceeds the circuit tree capacity"
        );
    }
    let t = &gc.targets;
    let mut pw = PartialWitness::<F>::new();
    pw.set_hash_target(t.block_id, bid);
    pw.set_target(t.group_index, F::from_canonical_u64(group_index));
    pw.set_hash_target(t.group_digest, group_digest_mode(txs, gc.k_max, gc.mode));
    pw.set_target(t.tx_count, F::from_canonical_u64(txs.len() as u64));

    let padded = txs.len() < gc.k_max;
    let filler_msg = HashOut { elements: [F::from_canonical_u64(0xDEAD_0000); 4] };
    let filler_sig = filler_wots_signature();

    let filler_xmss = match gc.mode {
        GroupMode::Xmss { height } if padded => Some(filler_xmss_for(height)),
        _ => None,
    };

    for i in 0..gc.k_max {
        let real = i < txs.len();
        pw.set_bool_target(t.live[i], real);
        let (msg, sig) = if real {
            (txs[i].msg, sigmas[i].clone())
        } else {
            (filler_msg, filler_sig.clone())
        };
        pw.set_hash_target(t.msgs[i], msg);
        for (st, sv) in t.sigmas[i].iter().zip(sig.iter()) {
            pw.set_hash_target(*st, *sv);
        }
        if let GroupMode::Xmss { height } = gc.mode {
            let (root, path, index, xsig) = if real {
                (txs[i].pk, paths[i].clone(), txs[i].index, sigmas[i].clone())
            } else {
                let fx = filler_xmss.as_ref().unwrap();
                (fx.0, fx.1.clone(), 0u64, fx.2.clone())
            };
            if !real {
                pw.set_hash_target(t.msgs[i], fx_msg());
                for (st, sv) in t.sigmas[i].iter().zip(xsig.iter()) {
                    pw.set_hash_target(*st, *sv);
                }
            }
            pw.set_hash_target(t.roots[i], root);
            for (pt, pv) in t.paths[i].iter().zip(path.iter()) {
                pw.set_hash_target(*pt, *pv);
            }
            for (lv, bt) in t.index_bits[i].iter().enumerate() {
                let _ = height;
                pw.set_bool_target(*bt, (index >> lv) & 1 == 1);
            }
        }
    }
    gc.data.prove(pw)
}

fn fx_msg() -> HashOut<F> {
    HashOut { elements: [F::from_canonical_u64(0xF111_0000); 4] }
}

fn filler_wots_signature() -> Vec<HashOut<F>> {
    static FILLER: OnceLock<Vec<HashOut<F>>> = OnceLock::new();
    FILLER
        .get_or_init(|| {
            let kp = wots_poseidon::keygen(0xF111_E500, L);
            let msg = HashOut { elements: [F::from_canonical_u64(0xDEAD_0000); 4] };
            wots_poseidon::sign(&kp, &digits_of(msg))
        })
        .clone()
}

fn filler_xmss_for(height: usize) -> FillerXmss {
    static CACHE: OnceLock<Mutex<HashMap<usize, FillerXmss>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(cached) = cache.lock().expect("filler cache poisoned").get(&height) {
        return cached.clone();
    }
    let built = build_filler_xmss(height);
    cache
        .lock()
        .expect("filler cache poisoned")
        .insert(height, built.clone());
    built
}

type FillerXmss = (HashOut<F>, Vec<HashOut<F>>, Vec<HashOut<F>>);
fn build_filler_xmss(height: usize) -> FillerXmss {
    let x = wots_poseidon::xmss_keygen(0xF111_1111, height, L);
    let d = digits_of(fx_msg());
    let sig = wots_poseidon::sign(&x.keys[0], &d);
    let path = wots_poseidon::xmss_auth_path(&x, 0);
    (x.root, path, sig)
}

fn common_data_for_step<
    Fq: RichField + Extendable<DQ>,
    Cq: GenericConfig<DQ, F = Fq>,
    const DQ: usize,
>(
    foreign: Option<&CommonCircuitData<Fq, DQ>>,
    pad_bits: usize,
    config: &CircuitConfig,
) -> CommonCircuitData<Fq, DQ>
where
    Cq::Hasher: AlgebraicHasher<Fq>,
{
    let builder = CircuitBuilder::<Fq, DQ>::new(config.clone());
    let data = builder.build::<Cq>();

    let mut builder = CircuitBuilder::<Fq, DQ>::new(config.clone());
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let vd = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<Cq>(&proof, &vd, &data.common);
    let data = builder.build::<Cq>();

    let mut builder = CircuitBuilder::<Fq, DQ>::new(config.clone());
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let vd = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<Cq>(&proof, &vd, &data.common);
    if let Some(fc) = foreign {
        let fp = builder.add_virtual_proof_with_pis(fc);
        let fvd = builder.add_virtual_verifier_data(fc.config.fri_config.cap_height);
        builder.verify_proof::<Cq>(&fp, &fvd, fc);
    }
    let num_consts = builder.config.num_constants;
    builder.add_gate_to_gate_set(GateRef::new(ConstantGate::new(num_consts)));
    if std::env::var_os("PCB_SHAPE").is_some() {
        eprintln!("[shape] goal natural gates = {}", builder.num_gates());
    }
    while builder.num_gates() < (1 << pad_bits) - PAD_HEADROOM {
        builder.add_gate(NoopGate, vec![]);
    }
    builder.build::<Cq>().common
}

const PAD_HEADROOM: usize = 64;

fn pad_to(b: &mut CircuitBuilder<F, D>, pad_bits: usize) {
    if std::env::var_os("PCB_SHAPE").is_some() {
        eprintln!("[shape] real natural gates = {}", b.num_gates());
    }
    while b.num_gates() < (1 << pad_bits) - PAD_HEADROOM {
        b.add_gate(NoopGate, vec![]);
    }
}

fn connect_cyclic_vd(
    b: &mut CircuitBuilder<F, D>,
    pt: &ProofWithPublicInputsTarget<D>,
    common: &CommonCircuitData<F, D>,
    vd: &VerifierCircuitTarget,
) {
    let cap_len = common.config.fri_config.num_cap_elements();
    let pis = &pt.public_inputs;
    let n = pis.len();
    let digest_start = n - 4 - 4 * cap_len;
    for j in 0..4 {
        b.connect(pis[digest_start + j], vd.circuit_digest.elements[j]);
    }
    for i in 0..cap_len {
        for j in 0..4 {
            b.connect(pis[n - 4 * (cap_len - i) + j], vd.constants_sigmas_cap.0[i].elements[j]);
        }
    }
}

pub const BPI_BLOCK_ID: usize = 0;
pub const BPI_ACC: usize = 4;
pub const BPI_NUM_GROUPS: usize = 8;
pub const BPI_NUM_TXS: usize = 9;
pub const BPI_GROUP_CIRCUIT_ID: usize = 10;
pub const BPI_GROUP_BUDGET: usize = 14;
pub const BLOCK_NUM_PI_LOGICAL: usize = 15;

fn constrain_counter(b: &mut CircuitBuilder<F, D>, value: Target, maximum: u64) {
    assert!((1..=u32::MAX as u64).contains(&maximum));
    let bits = (u64::BITS - maximum.leading_zeros()) as usize;
    b.range_check(value, bits);
    let limit = b.constant(F::from_canonical_u64(maximum));
    let slack = b.sub(limit, value);
    b.range_check(slack, bits);
}

pub struct BlockCircuit {
    pub data: CircuitData<F, C, D>,
    pub common: CommonCircuitData<F, D>,
    condition: BoolTarget,
    inner: ProofWithPublicInputsTarget<D>,
    group_pts: Vec<ProofWithPublicInputsTarget<D>>,
    additional_group_active: Vec<BoolTarget>,
    block_id: HashOutTarget,
    verifier_data_target: VerifierCircuitTarget,
    pub k_max: usize,
    pub group_circuit_id: HashOut<F>,
    pub fan_in: usize,
    pub max_groups: u64,
    base_proof: ProofWithPublicInputs<F, C, D>,
}

pub const BLOCK_PAD_BITS: usize = 14;
pub const CHAIN_PAD_BITS: usize = 14;

fn block_pad_bits(query_rounds: usize, fan_in: usize) -> usize {
    let query_bits = if query_rounds > DEFAULT_FRI_QUERY_ROUNDS { 15 } else { BLOCK_PAD_BITS };
    query_bits + usize::from(fan_in > 1)
}

fn chain_pad_bits(query_rounds: usize) -> usize {
    if query_rounds > 76 {
        16
    } else if query_rounds > DEFAULT_FRI_QUERY_ROUNDS {
        15
    } else {
        CHAIN_PAD_BITS
    }
}

pub fn build_block_circuit(gc: &GroupCircuit) -> BlockCircuit {
    build_block_circuit_with_fan_in(gc, 1)
}

pub fn build_block_circuit_with_fan_in(gc: &GroupCircuit, fan_in: usize) -> BlockCircuit {
    build_block_circuit_with_limit(gc, fan_in, MAX_BLOCK_GROUPS)
}

fn build_block_circuit_with_limit(
    gc: &GroupCircuit,
    fan_in: usize,
    max_groups: u64,
) -> BlockCircuit {
    assert!((1..=2).contains(&fan_in), "block fan-in must be one or two");
    let max_txs = max_groups.checked_mul(gc.k_max as u64).expect("transaction limit overflow");
    assert!((1..=u32::MAX as u64).contains(&max_txs));
    let config = gc.data.common.config.clone();
    let mut b = CircuitBuilder::<F, D>::new(config.clone());

    let block_id = b.add_virtual_hash();
    b.register_public_inputs(&block_id.elements);
    let acc_out = b.add_virtual_hash();
    b.register_public_inputs(&acc_out.elements);
    let num_groups = b.add_virtual_public_input();
    let num_txs = b.add_virtual_public_input();
    let block_group_circuit_id = b.add_virtual_hash();
    b.register_public_inputs(&block_group_circuit_id.elements);
    let block_group_budget = b.add_virtual_public_input();

    let pad_bits = block_pad_bits(gc.query_rounds, fan_in);
    let mut common_data =
        common_data_for_step::<F, C, D>(Some(&gc.data.common), pad_bits, &config);
    let verifier_data_target = b.add_verifier_data_public_inputs();
    common_data.num_public_inputs = b.num_public_inputs();

    let condition = b.add_virtual_bool_target_safe();
    let inner = b.add_virtual_proof_with_pis(&common_data);
    let in_block_id = HashOutTarget::try_from(&inner.public_inputs[BPI_BLOCK_ID..BPI_BLOCK_ID + 4])
        .expect("block id slice");
    let in_acc =
        HashOutTarget::try_from(&inner.public_inputs[BPI_ACC..BPI_ACC + 4]).expect("acc slice");
    let in_ng = inner.public_inputs[BPI_NUM_GROUPS];
    let in_nt = inner.public_inputs[BPI_NUM_TXS];

    let group_vd = b.constant_verifier_data(&gc.data.verifier_only);
    let expected_circuit_id = HashOutTarget {
        elements: core::array::from_fn(|j| b.constant(gc.circuit_id.elements[j])),
    };
    let expected_budget = b.constant(F::from_canonical_u64(gc.k_max as u64));
    b.connect_hashes(block_group_circuit_id, expected_circuit_id);
    b.connect(block_group_budget, expected_budget);
    let carried_id = select_hash(&mut b, condition, in_block_id, block_id);
    b.connect_hashes(block_id, carried_id);

    let zero_h = {
        let z = b.zero();
        HashOutTarget { elements: [z; 4] }
    };
    let prev_acc = select_hash(&mut b, condition, in_acc, zero_h);
    let prev_ng = b.mul(condition.target, in_ng);
    let prev_nt = b.mul(condition.target, in_nt);
    constrain_counter(&mut b, prev_ng, max_groups);
    constrain_counter(&mut b, prev_nt, max_txs);

    let one = b.one();
    let mut running_acc = prev_acc;
    let mut running_ng = prev_ng;
    let mut running_nt = prev_nt;
    let mut group_pts = Vec::with_capacity(fan_in);
    let mut additional_group_active = Vec::with_capacity(fan_in.saturating_sub(1));
    let mut first_group_pis: Option<Vec<Target>> = None;

    for slot in 0..fan_in {
        let group_pt = b.add_virtual_proof_with_pis(&gc.data.common);
        b.verify_proof::<C>(&group_pt, &group_vd, &gc.data.common);
        let active = if slot == 0 {
            None
        } else {
            let flag = b.add_virtual_bool_target_safe();
            additional_group_active.push(flag);
            Some(flag)
        };

        if let Some(flag) = active {
            let first_pis = first_group_pis
                .as_ref()
                .expect("the first group-proof slot must already exist");
            for (&first_pi, &slot_pi) in first_pis.iter().zip(&group_pt.public_inputs) {
                let padding_pi = b.select(flag, first_pi, slot_pi);
                b.connect(padding_pi, first_pi);
            }
        } else {
            first_group_pis = Some(group_pt.public_inputs.clone());
        }

        let g_block_id =
            HashOutTarget::try_from(&group_pt.public_inputs[GPI_BLOCK_ID..GPI_BLOCK_ID + 4])
                .expect("group block id");
        let g_index = group_pt.public_inputs[GPI_GROUP_INDEX];
        let g_circuit_id =
            HashOutTarget::try_from(&group_pt.public_inputs[GPI_CIRCUIT_ID..GPI_CIRCUIT_ID + 4])
                .expect("group circuit id");
        let g_budget = group_pt.public_inputs[GPI_GROUP_BUDGET];
        let g_digest = HashOutTarget::try_from(
            &group_pt.public_inputs[GPI_GROUP_DIGEST..GPI_GROUP_DIGEST + 4],
        )
        .expect("group digest");
        let g_count = group_pt.public_inputs[GPI_TX_COUNT];

        b.connect_hashes(g_block_id, block_id);
        b.connect_hashes(g_circuit_id, expected_circuit_id);
        b.connect(g_budget, expected_budget);

        let index_to_check = match active {
            Some(flag) => b.select(flag, g_index, running_ng),
            None => g_index,
        };
        b.connect(index_to_check, running_ng);

        let mut fold_in = vec![b.constant(dom(DOM_ACC))];
        fold_in.extend_from_slice(&running_acc.elements);
        fold_in.extend_from_slice(&g_digest.elements);
        let candidate_acc = hash_targets(&mut b, fold_in);
        running_acc = match active {
            Some(flag) => select_hash(&mut b, flag, candidate_acc, running_acc),
            None => candidate_acc,
        };

        let active_target = active.map_or(one, |flag| flag.target);
        running_ng = b.add(running_ng, active_target);
        let live_count = b.mul(active_target, g_count);
        running_nt = b.add(running_nt, live_count);
        group_pts.push(group_pt);
    }

    b.connect_hashes(acc_out, running_acc);
    b.connect(num_groups, running_ng);
    b.connect(num_txs, running_nt);
    constrain_counter(&mut b, num_groups, max_groups);
    constrain_counter(&mut b, num_txs, max_txs);

    b.conditionally_verify_cyclic_proof_or_dummy::<C>(condition, &inner, &common_data)
        .expect("block accumulator cyclic wiring failed");
    pad_to(&mut b, pad_bits);

    let data = b.build::<C>();
    let base_proof =
        cyclic_base_proof::<F, C, D>(&common_data, &data.verifier_only, Default::default());
    BlockCircuit {
        data,
        base_proof,
        common: common_data,
        condition,
        inner,
        group_pts,
        additional_group_active,
        block_id,
        verifier_data_target,
        k_max: gc.k_max,
        group_circuit_id: gc.circuit_id,
        fan_in,
        max_groups,
    }
}

impl BlockCircuit {
    pub fn step(
        &self,
        bid: HashOut<F>,
        group_proof: &ProofWithPublicInputs<F, C, D>,
        prev: Option<&ProofWithPublicInputs<F, C, D>>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        self.step_batch(bid, std::slice::from_ref(group_proof), prev)
    }

    pub fn step_batch(
        &self,
        bid: HashOut<F>,
        group_proofs: &[ProofWithPublicInputs<F, C, D>],
        prev: Option<&ProofWithPublicInputs<F, C, D>>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let padding_proof = group_proofs
            .first()
            .ok_or_else(|| anyhow::anyhow!("a block step must consume at least one group"))?;
        self.step_batch_with_padding(bid, group_proofs, prev, padding_proof)
    }

    fn step_batch_with_padding(
        &self,
        bid: HashOut<F>,
        group_proofs: &[ProofWithPublicInputs<F, C, D>],
        prev: Option<&ProofWithPublicInputs<F, C, D>>,
        padding_proof: &ProofWithPublicInputs<F, C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        anyhow::ensure!(
            !group_proofs.is_empty(),
            "a block step must consume at least one group"
        );
        anyhow::ensure!(
            group_proofs.len() <= self.fan_in,
            "block step exceeds its fixed fan-in"
        );
        let mut next_group_index = if let Some(previous) = prev {
            anyhow::ensure!(
                previous.public_inputs.len() >= BLOCK_NUM_PI_LOGICAL,
                "previous block proof has too few public inputs"
            );
            anyhow::ensure!(
                previous.public_inputs[BPI_BLOCK_ID..BPI_BLOCK_ID + 4] == bid.elements,
                "previous block proof belongs to a different block"
            );
            anyhow::ensure!(
                previous.public_inputs[BPI_GROUP_CIRCUIT_ID..BPI_GROUP_CIRCUIT_ID + 4]
                    == self.group_circuit_id.elements,
                "previous block proof uses a different group circuit"
            );
            anyhow::ensure!(
                previous.public_inputs[BPI_GROUP_BUDGET]
                    == F::from_canonical_u64(self.k_max as u64),
                "previous block proof uses a different group budget"
            );
            previous.public_inputs[BPI_NUM_GROUPS].to_canonical_u64()
        } else {
            0
        };
        anyhow::ensure!(
            next_group_index
                .checked_add(group_proofs.len() as u64)
                .is_some_and(|count| count <= self.max_groups),
            "block exceeds its group-count limit"
        );
        for proof in group_proofs {
            anyhow::ensure!(
                proof.public_inputs.len() >= GROUP_NUM_PI,
                "group proof has too few public inputs"
            );
            anyhow::ensure!(
                proof.public_inputs[GPI_BLOCK_ID..GPI_BLOCK_ID + 4] == bid.elements,
                "group proof belongs to a different block"
            );
            anyhow::ensure!(
                proof.public_inputs[GPI_GROUP_INDEX]
                    == F::from_canonical_u64(next_group_index),
                "group proof index is not the next unconsumed index"
            );
            anyhow::ensure!(
                proof.public_inputs[GPI_CIRCUIT_ID..GPI_CIRCUIT_ID + 4]
                    == self.group_circuit_id.elements,
                "group proof uses a different circuit family"
            );
            anyhow::ensure!(
                proof.public_inputs[GPI_GROUP_BUDGET]
                    == F::from_canonical_u64(self.k_max as u64),
                "group proof uses a different fixed budget"
            );
            next_group_index = next_group_index
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("group index overflow"))?;
        }
        if group_proofs.len() < self.fan_in {
            anyhow::ensure!(
                padding_proof.public_inputs == group_proofs[0].public_inputs,
                "an inactive slot must repeat the first slot's public statement"
            );
        }
        self.prove_step_witness(bid, group_proofs, prev, padding_proof)
    }

    #[doc(hidden)]
    pub fn step_unchecked(
        &self,
        bid: HashOut<F>,
        group_proof: &ProofWithPublicInputs<F, C, D>,
        prev: Option<&ProofWithPublicInputs<F, C, D>>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        self.prove_step_witness(bid, std::slice::from_ref(group_proof), prev, group_proof)
    }

    fn prove_step_witness(
        &self,
        bid: HashOut<F>,
        group_proofs: &[ProofWithPublicInputs<F, C, D>],
        prev: Option<&ProofWithPublicInputs<F, C, D>>,
        padding_proof: &ProofWithPublicInputs<F, C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        pw.set_bool_target(self.condition, prev.is_some());
        pw.set_hash_target(self.block_id, bid);
        for (slot, target) in self.group_pts.iter().enumerate() {
            let proof = group_proofs.get(slot).unwrap_or(padding_proof);
            pw.set_proof_with_pis_target(target, proof);
        }
        for (offset, target) in self.additional_group_active.iter().enumerate() {
            pw.set_bool_target(*target, offset + 1 < group_proofs.len());
        }
        match prev {
            Some(p) => pw.set_proof_with_pis_target(&self.inner, p),
            None => pw.set_proof_with_pis_target(&self.inner, &self.base_proof),
        }
        pw.set_verifier_data_target(&self.verifier_data_target, &self.data.verifier_only);
        self.data.prove(pw)
    }

    pub fn verify_block(
        &self,
        proof: &ProofWithPublicInputs<F, C, D>,
        expect_block_id: HashOut<F>,
        expect_acc: HashOut<F>,
        expect_groups: u64,
        expect_txs: u64,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            (1..=self.max_groups).contains(&expect_groups)
                && expect_txs <= self.max_groups * self.k_max as u64,
            "block counters exceed protocol limits"
        );
        self.data.verify(proof.clone())?;
        check_cyclic_proof_verifier_data(proof, &self.data.verifier_only, &self.data.common)?;
        let pis = &proof.public_inputs;
        anyhow::ensure!(
            pis[BPI_BLOCK_ID..BPI_BLOCK_ID + 4] == expect_block_id.elements,
            "block id mismatch"
        );
        anyhow::ensure!(pis[BPI_ACC..BPI_ACC + 4] == expect_acc.elements, "tx commitment mismatch");
        anyhow::ensure!(
            pis[BPI_NUM_GROUPS] == F::from_canonical_u64(expect_groups),
            "group count mismatch"
        );
        anyhow::ensure!(
            pis[BPI_NUM_TXS] == F::from_canonical_u64(expect_txs),
            "transaction count mismatch"
        );
        anyhow::ensure!(
            pis[BPI_GROUP_CIRCUIT_ID..BPI_GROUP_CIRCUIT_ID + 4] == self.group_circuit_id.elements,
            "group circuit id mismatch"
        );
        anyhow::ensure!(
            pis[BPI_GROUP_BUDGET] == F::from_canonical_u64(self.k_max as u64),
            "group budget mismatch"
        );
        Ok(())
    }
}

pub const CPI_GENESIS: usize = 0;
pub const CPI_CHAIN_COMMIT: usize = 4;
pub const CPI_HEIGHT: usize = 8;
pub const CPI_TIP_HASH: usize = 9;
pub const CPI_VK_DIGEST: usize = 13;
pub const CHAIN_NUM_PI_LOGICAL: usize = 17;

pub struct ChainCircuit {
    pub data: CircuitData<F, C, D>,
    pub common: CommonCircuitData<F, D>,
    condition: BoolTarget,
    inner: ProofWithPublicInputsTarget<D>,
    block_pt: ProofWithPublicInputsTarget<D>,
    genesis: HashOutTarget,
    height: Target,
    prev_hash: HashOutTarget,
    pub vk_digest: HashOut<F>,
    pub max_blocks: u64,
    base_proof: ProofWithPublicInputs<F, C, D>,
}

pub fn chain_vk_digest(bc: &BlockCircuit, gc: &GroupCircuit) -> HashOut<F> {
    chain_vk_digest_with_limit(bc, gc, MAX_CHAIN_BLOCKS)
}

fn chain_vk_digest_with_limit(
    bc: &BlockCircuit,
    gc: &GroupCircuit,
    max_blocks: u64,
) -> HashOut<F> {
    let mut v = vec![dom(DOM_VK)];
    v.extend_from_slice(&bc.data.verifier_only.circuit_digest.elements);
    v.extend_from_slice(&gc.data.verifier_only.circuit_digest.elements);
    v.push(F::from_canonical_u64(PCB_VERSION));
    v.push(F::from_canonical_u64(max_blocks));
    PoseidonHash::hash_no_pad(&v)
}

pub fn build_chain_circuit(bc: &BlockCircuit, gc: &GroupCircuit) -> ChainCircuit {
    build_chain_circuit_with_limit(bc, gc, MAX_CHAIN_BLOCKS)
}

fn build_chain_circuit_with_limit(
    bc: &BlockCircuit,
    gc: &GroupCircuit,
    max_blocks: u64,
) -> ChainCircuit {
    assert_eq!(
        bc.data.common.config.fri_config.num_query_rounds,
        gc.query_rounds,
        "block and group circuits must use the same FRI query budget"
    );
    let vkd = chain_vk_digest_with_limit(bc, gc, max_blocks);
    let config = bc.data.common.config.clone();
    let mut b = CircuitBuilder::<F, D>::new(config.clone());

    let genesis = b.add_virtual_hash();
    b.register_public_inputs(&genesis.elements);
    let chain_commit = b.add_virtual_hash();
    b.register_public_inputs(&chain_commit.elements);
    let height = b.add_virtual_public_input();
    let tip = b.add_virtual_hash();
    b.register_public_inputs(&tip.elements);
    let vk_digest_t = b.add_virtual_hash();
    b.register_public_inputs(&vk_digest_t.elements);

    let pad_bits = chain_pad_bits(gc.query_rounds);
    let mut common_data =
        common_data_for_step::<F, C, D>(Some(&bc.data.common), pad_bits, &config);
    let verifier_data_target = b.add_verifier_data_public_inputs();
    common_data.num_public_inputs = b.num_public_inputs();

    let condition = b.add_virtual_bool_target_safe();
    let inner = b.add_virtual_proof_with_pis(&common_data);
    let in_genesis =
        HashOutTarget::try_from(&inner.public_inputs[CPI_GENESIS..CPI_GENESIS + 4]).unwrap();
    let in_commit =
        HashOutTarget::try_from(&inner.public_inputs[CPI_CHAIN_COMMIT..CPI_CHAIN_COMMIT + 4])
            .unwrap();
    let in_height = inner.public_inputs[CPI_HEIGHT];
    let in_tip =
        HashOutTarget::try_from(&inner.public_inputs[CPI_TIP_HASH..CPI_TIP_HASH + 4]).unwrap();
    let in_vkd =
        HashOutTarget::try_from(&inner.public_inputs[CPI_VK_DIGEST..CPI_VK_DIGEST + 4]).unwrap();

    let block_vd = b.constant_verifier_data(&bc.data.verifier_only);
    let block_pt = b.add_virtual_proof_with_pis(&bc.data.common);
    b.verify_proof::<C>(&block_pt, &block_vd, &bc.data.common);
    connect_cyclic_vd(&mut b, &block_pt, &bc.data.common, &block_vd);

    let b_block_id =
        HashOutTarget::try_from(&block_pt.public_inputs[BPI_BLOCK_ID..BPI_BLOCK_ID + 4]).unwrap();
    let b_acc = HashOutTarget::try_from(&block_pt.public_inputs[BPI_ACC..BPI_ACC + 4]).unwrap();
    let b_ng = block_pt.public_inputs[BPI_NUM_GROUPS];
    let b_nt = block_pt.public_inputs[BPI_NUM_TXS];

    let vkd_const = {
        let e: [Target; 4] = core::array::from_fn(|j| b.constant(vkd.elements[j]));
        HashOutTarget { elements: e }
    };
    b.connect_hashes(vk_digest_t, vkd_const);
    let carried_vkd = select_hash(&mut b, condition, in_vkd, vkd_const);
    b.connect_hashes(vk_digest_t, carried_vkd);

    let prev_hash = b.add_virtual_hash();
    let one = b.one();
    let prev_height = b.mul(condition.target, in_height);
    constrain_counter(&mut b, prev_height, max_blocks);
    let expect_height = b.add(prev_height, one);
    b.connect(height, expect_height);
    constrain_counter(&mut b, height, max_blocks);

    let expect_prev = select_hash(&mut b, condition, in_tip, genesis);
    b.connect_hashes(prev_hash, expect_prev);

    let carried_genesis = select_hash(&mut b, condition, in_genesis, genesis);
    b.connect_hashes(genesis, carried_genesis);

    let mut bid_in = vec![b.constant(dom(DOM_BLOCK_ID)), height];
    bid_in.extend_from_slice(&prev_hash.elements);
    bid_in.extend_from_slice(&b_acc.elements);
    bid_in.push(b.constant(F::from_canonical_u64(PCB_VERSION)));
    let computed_bid = hash_targets(&mut b, bid_in);
    b.connect_hashes(computed_bid, b_block_id);

    let mut tip_in = vec![b.constant(dom(DOM_TIP))];
    tip_in.extend_from_slice(&b_block_id.elements);
    tip_in.extend_from_slice(&b_acc.elements);
    tip_in.push(b_ng);
    tip_in.push(b_nt);
    let new_tip = hash_targets(&mut b, tip_in);
    b.connect_hashes(tip, new_tip);

    let prev_commit = select_hash(&mut b, condition, in_commit, genesis);
    let mut cc_in = vec![b.constant(dom(DOM_CHAIN))];
    cc_in.extend_from_slice(&prev_commit.elements);
    cc_in.extend_from_slice(&new_tip.elements);
    let new_commit = hash_targets(&mut b, cc_in);
    b.connect_hashes(chain_commit, new_commit);

    b.conditionally_verify_cyclic_proof_or_dummy::<C>(condition, &inner, &common_data)
        .expect("chain step cyclic wiring failed");
    pad_to(&mut b, pad_bits);

    let data = b.build::<C>();
    let _ = verifier_data_target;
    let base_proof =
        cyclic_base_proof::<F, C, D>(&common_data, &data.verifier_only, Default::default());
    ChainCircuit {
        data,
        base_proof,
        common: common_data,
        condition,
        inner,
        block_pt,
        genesis,
        height,
        prev_hash,
        vk_digest: vkd,
        max_blocks,
    }
}

impl ChainCircuit {
    fn verifier_data_target(&self) -> VerifierCircuitTarget {
        let cap_len = self.data.common.config.fri_config.num_cap_elements();
        let pis = &self.data.prover_only.public_inputs;
        let n = pis.len();
        let digest_start = n - 4 - 4 * cap_len;
        VerifierCircuitTarget {
            circuit_digest: HashOutTarget {
                elements: core::array::from_fn(|j| pis[digest_start + j]),
            },
            constants_sigmas_cap: plonky2::hash::hash_types::MerkleCapTarget(
                (0..cap_len)
                    .map(|i| HashOutTarget {
                        elements: core::array::from_fn(|j| pis[n - 4 * (cap_len - i) + j]),
                    })
                    .collect(),
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn step(
        &self,
        genesis: HashOut<F>,
        height: u64,
        prev_hash: HashOut<F>,
        block_proof: &ProofWithPublicInputs<F, C, D>,
        prev: Option<&ProofWithPublicInputs<F, C, D>>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        anyhow::ensure!(
            (1..=self.max_blocks).contains(&height),
            "chain height exceeds protocol limits"
        );
        self.step_unchecked(genesis, height, prev_hash, block_proof, prev)
    }

    #[doc(hidden)]
    pub fn step_unchecked(
        &self,
        genesis: HashOut<F>,
        height: u64,
        prev_hash: HashOut<F>,
        block_proof: &ProofWithPublicInputs<F, C, D>,
        prev: Option<&ProofWithPublicInputs<F, C, D>>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        pw.set_bool_target(self.condition, prev.is_some());
        pw.set_hash_target(self.genesis, genesis);
        pw.set_target(self.height, F::from_canonical_u64(height));
        pw.set_hash_target(self.prev_hash, prev_hash);
        pw.set_proof_with_pis_target(&self.block_pt, block_proof);
        match prev {
            Some(p) => pw.set_proof_with_pis_target(&self.inner, p),
            None => pw.set_proof_with_pis_target(&self.inner, &self.base_proof),
        }
        pw.set_verifier_data_target(&self.verifier_data_target(), &self.data.verifier_only);
        self.data.prove(pw)
    }

    pub fn verify_chain(
        &self,
        proof: &ProofWithPublicInputs<F, C, D>,
        expect_genesis: HashOut<F>,
    ) -> anyhow::Result<(u64, HashOut<F>, HashOut<F>)> {
        self.data.verify(proof.clone())?;
        check_cyclic_proof_verifier_data(proof, &self.data.verifier_only, &self.data.common)?;
        let pis = &proof.public_inputs;
        anyhow::ensure!(
            pis[CPI_VK_DIGEST..CPI_VK_DIGEST + 4] == self.vk_digest.elements,
            "circuit-family digest mismatch"
        );
        anyhow::ensure!(
            pis[CPI_GENESIS..CPI_GENESIS + 4] == expect_genesis.elements,
            "genesis mismatch"
        );
        let h = pis[CPI_HEIGHT].to_canonical_u64();
        anyhow::ensure!(
            (1..=self.max_blocks).contains(&h),
            "chain height exceeds protocol limits"
        );
        let commit = HashOut { elements: core::array::from_fn(|j| pis[CPI_CHAIN_COMMIT + j]) };
        let tip = HashOut { elements: core::array::from_fn(|j| pis[CPI_TIP_HASH + j]) };
        Ok((h, commit, tip))
    }
}

pub struct BuiltBlock {
    pub groups: Vec<Vec<Tx>>,
    pub sigs: Vec<Vec<Vec<HashOut<F>>>>,
    pub tx_root: HashOut<F>,
    pub num_txs: u64,
}

pub fn make_block(seed: u64, k: usize, k_max: usize) -> BuiltBlock {
    let mut groups = Vec::new();
    let mut sigs = Vec::new();
    let mut cur_t = Vec::new();
    let mut cur_s = Vec::new();
    for i in 0..k {
        let kp = wots_poseidon::keygen(seed.wrapping_mul(0x9E37_79B9).wrapping_add(i as u64), L);
        let msg = PoseidonHash::hash_no_pad(&[
            F::from_canonical_u64(seed),
            F::from_canonical_u64(i as u64),
            F::from_canonical_u64(0x7A11),
            F::from_canonical_u64(0x0B0C),
        ]);
        let d = digits_of(msg);
        let sig = wots_poseidon::sign(&kp, &d);
        let tx = Tx { pk: kp.pk, msg, index: 0 };
        debug_assert!(native_verify(&tx, &sig));
        cur_t.push(tx);
        cur_s.push(sig);
        if cur_t.len() == k_max {
            groups.push(std::mem::take(&mut cur_t));
            sigs.push(std::mem::take(&mut cur_s));
        }
    }
    if !cur_t.is_empty() {
        groups.push(cur_t);
        sigs.push(cur_s);
    }
    let root = tx_root(&groups, k_max);
    BuiltBlock { groups, sigs, tx_root: root, num_txs: k as u64 }
}

pub struct BuiltXmssBlock {
    pub groups: Vec<Vec<Tx>>,
    pub sigs: Vec<Vec<Vec<HashOut<F>>>>,
    pub paths: Vec<Vec<Vec<HashOut<F>>>>,
    pub tx_root: HashOut<F>,
    pub num_txs: u64,
}

pub fn make_xmss_block(seed: u64, k: usize, k_max: usize, h: usize) -> BuiltXmssBlock {
    assert!(k_max > 0, "group budget must be positive");
    assert!(
        h < usize::BITS as usize,
        "XMSS tree height exceeds the host index width"
    );
    let capacity = 1usize << h;
    assert!(
        k <= capacity,
        "transaction count exceeds XMSS tree capacity"
    );
    let x = wots_poseidon::xmss_keygen(seed, h, L);
    make_xmss_block_from_tree(&x, 0, k, k_max, seed)
}

pub fn make_xmss_block_from_tree(
    x: &wots_poseidon::Xmss,
    first_index: usize,
    k: usize,
    k_max: usize,
    message_seed: u64,
) -> BuiltXmssBlock {
    assert!(k > 0, "transaction count must be positive");
    assert!(k_max > 0, "group budget must be positive");
    assert_eq!(x.l, L, "XMSS tree uses a different WOTS parameter set");
    let end_index = first_index
        .checked_add(k)
        .expect("XMSS leaf range overflows the host index width");
    assert!(
        end_index <= x.keys.len(),
        "transaction range exceeds XMSS tree capacity"
    );

    let mut groups = Vec::new();
    let mut sigs = Vec::new();
    let mut paths = Vec::new();
    let (mut ct, mut cs, mut cp) = (Vec::new(), Vec::new(), Vec::new());
    for offset in 0..k {
        let index = first_index + offset;
        let msg = PoseidonHash::hash_no_pad(&[
            F::from_canonical_u64(message_seed),
            F::from_canonical_u64(index as u64),
            F::from_canonical_u64(0x584D),
            F::from_canonical_u64(0x5353),
        ]);
        let d = digits_of(msg);
        let sig = wots_poseidon::sign(&x.keys[index], &d);
        let path = wots_poseidon::xmss_auth_path(&x, index);
        debug_assert!(wots_poseidon::xmss_verify(x.root, &d, &sig, &path, index));
        ct.push(Tx { pk: x.root, msg, index: index as u64 });
        cs.push(sig);
        cp.push(path);
        if ct.len() == k_max {
            groups.push(std::mem::take(&mut ct));
            sigs.push(std::mem::take(&mut cs));
            paths.push(std::mem::take(&mut cp));
        }
    }
    if !ct.is_empty() {
        groups.push(ct);
        sigs.push(cs);
        paths.push(cp);
    }
    let root = tx_root_mode(&groups, k_max, GroupMode::Xmss { height: x.h });
    BuiltXmssBlock { groups, sigs, paths, tx_root: root, num_txs: k as u64 }
}

pub fn detect_index_reuse(blocks: &[Vec<Tx>]) -> Vec<(HashOut<F>, u64)> {
    let mut seen = std::collections::HashSet::new();
    let mut dup = Vec::new();
    for b in blocks {
        for t in b {
            let key = (t.pk.elements.map(|e| e.to_canonical_u64()), t.index);
            if !seen.insert(key) {
                dup.push((t.pk, t.index));
            }
        }
    }
    dup
}

pub mod binding_probe {
    use super::*;

    pub struct TupleCircuit {
        pub data: CircuitData<F, C, D>,
        messages: Vec<HashOutTarget>,
        signatures: Vec<Vec<HashOutTarget>>,
        keys: Vec<HashOutTarget>,
        digest: HashOutTarget,
        bind: bool,
        pub gates: usize,
    }

    pub fn build(budget: usize, queries: usize, bind: bool) -> TupleCircuit {
        let mut builder = CircuitBuilder::<F, D>::new(recursion_config(queries));
        let mut messages = Vec::new();
        let mut signatures = Vec::new();
        let mut keys = Vec::new();
        let mut leaves = vec![builder.constant(dom(DOM_GROUP))];
        for _ in 0..budget {
            let msg = builder.add_virtual_hash();
            let key = builder.add_virtual_hash();
            builder.register_public_inputs(&key.elements);
            builder.register_public_inputs(&msg.elements);
            let digits = derive_digits_target(&mut builder, msg);
            let mut ends = Vec::new();
            let mut sig = Vec::new();
            for digit in digits {
                let value = builder.add_virtual_hash();
                let end = chain_end_target(&mut builder, value, digit);
                ends.extend_from_slice(&end.elements);
                sig.push(value);
            }
            let recovered = hash_targets(&mut builder, ends);
            builder.connect_hashes(recovered, key);
            if bind {
                let mut input = vec![builder.constant(dom(DOM_TX_LEAF))];
                input.extend_from_slice(&key.elements);
                input.extend_from_slice(&msg.elements);
                leaves.extend_from_slice(&hash_targets(&mut builder, input).elements);
            }
            messages.push(msg);
            signatures.push(sig);
            keys.push(key);
        }
        let digest = builder.add_virtual_hash();
        builder.register_public_inputs(&digest.elements);
        let expected = if bind { hash_targets(&mut builder, leaves) } else {
            let zero = builder.zero();
            HashOutTarget { elements: [zero; 4] }
        };
        builder.connect_hashes(digest, expected);
        let gates = builder.num_gates();
        let data = builder.build::<C>();
        TupleCircuit { data, messages, signatures, keys, digest, bind, gates }
    }

    impl TupleCircuit {
        pub fn prove(&self, txs: &[Tx], signatures: &[Vec<HashOut<F>>])
            -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
            anyhow::ensure!(txs.len() == self.messages.len() && signatures.len() == txs.len(),
                            "probe requires full occupancy");
            let mut witness = PartialWitness::new();
            for (i, tx) in txs.iter().enumerate() {
                anyhow::ensure!(signatures[i].len() == L, "invalid signature width");
                witness.set_hash_target(self.keys[i], tx.pk);
                witness.set_hash_target(self.messages[i], tx.msg);
                for (target, value) in self.signatures[i].iter().zip(&signatures[i]) {
                    witness.set_hash_target(*target, *value);
                }
            }
            witness.set_hash_target(self.digest, if self.bind {
                group_digest(txs, txs.len())
            } else { zero_hash() });
            self.data.prove(witness)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn probe_verifies_signatures_and_binds_public_tuples() {
            let block = make_block(20260923, 1, 1);
            for bind in [false, true] {
                let circuit = build(1, 28, bind);
                let proof = circuit.prove(&block.groups[0], &block.sigs[0]).unwrap();
                circuit.data.verify(proof.clone()).unwrap();
                for index in [0, 4, 8] {
                    let mut changed = proof.clone();
                    changed.public_inputs[index] += F::ONE;
                    assert!(circuit.data.verify(changed).is_err());
                }
                let mut signatures = block.sigs[0].clone();
                signatures[0][0].elements[0] += F::ONE;
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    circuit.prove(&block.groups[0], &signatures)
                }));
                match outcome {
                    Ok(Ok(proof)) => assert!(circuit.data.verify(proof).is_err()),
                    Ok(Err(_)) => (),
                    Err(payload) => {
                        let message = payload.downcast_ref::<String>().map(String::as_str)
                            .or_else(|| payload.downcast_ref::<&str>().copied()).unwrap_or("");
                        assert!(message.contains("was set twice with different values"), "unexpected proving panic");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rejected_witness(data: &CircuitData<F, C, D>, witness: PartialWitness<F>) -> bool {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| data.prove(witness))) {
            Ok(Ok(proof)) => data.verify(proof).is_err(),
            Ok(Err(_)) => true,
            Err(payload) => {
                let message = payload.downcast_ref::<String>().map(String::as_str)
                    .or_else(|| payload.downcast_ref::<&str>().copied()).unwrap_or("");
                if message.contains("Partition containing")
                    && message.contains("was set twice with different values")
                {
                    true
                } else {
                    std::panic::resume_unwind(payload)
                }
            }
        }
    }

    #[test]
    fn canonical_bit_gadget_matches_integer_encoding() -> anyhow::Result<()> {
        let mut builder = CircuitBuilder::<F, D>::new(recursion_config(28));
        let value = builder.add_virtual_public_input();
        let bits = canonical_bits_64(&mut builder, value);
        let data = builder.build::<C>();
        let modulus = 0xffff_ffff_0000_0001u64;
        for x in [0, 1, (1 << 32) - 2, (1 << 32) - 1, 1 << 32, modulus - 1] {
            let mut witness = PartialWitness::new();
            witness.set_target(value, F::from_canonical_u64(x));
            for (i, bit) in bits.iter().enumerate() {
                witness.set_bool_target(*bit, (x >> i) & 1 == 1);
            }
            data.verify(data.prove(witness)?)?;
            if let Some(alternate) = x.checked_add(modulus) {
                let mut witness = PartialWitness::new();
                witness.set_target(value, F::from_canonical_u64(x));
                for (i, bit) in bits.iter().enumerate() {
                    witness.set_bool_target(*bit, (alternate >> i) & 1 == 1);
                }
                assert!(rejected_witness(&data, witness));
            }
        }
        Ok(())
    }

    #[test]
    fn counter_constraint_accepts_inclusive_limits_and_rejects_field_wrap() -> anyhow::Result<()> {
        for limit in [MAX_BLOCK_GROUPS, MAX_CHAIN_BLOCKS] {
            let mut builder = CircuitBuilder::<F, D>::new(recursion_config(28));
            let counter = builder.add_virtual_public_input();
            constrain_counter(&mut builder, counter, limit);
            let data = builder.build::<C>();
            for value in [0, 1, limit - 1, limit] {
                let mut witness = PartialWitness::new();
                witness.set_target(counter, F::from_canonical_u64(value));
                data.verify(data.prove(witness)?)?;
            }
            for value in [F::from_canonical_u64(limit + 1), F::NEG_ONE] {
                let mut witness = PartialWitness::new();
                witness.set_target(counter, value);
                assert!(rejected_witness(&data, witness));
            }
        }
        Ok(())
    }

    #[test]
    #[ignore = "proves recursive boundary cases, including witnesses that bypass the host API"]
    fn recursive_limits_hold_when_host_checks_are_bypassed() -> anyhow::Result<()> {
        let gc = build_group_circuit(1);
        let bc = build_block_circuit_with_limit(&gc, 1, 2);
        let cc = build_chain_circuit_with_limit(&bc, &gc, 2);
        let block = make_block(0xCA90, 3, 1);
        let genesis = zero_hash();
        let bid = block_id(1, genesis, block.tx_root);
        let proofs = block.groups.iter().zip(&block.sigs).enumerate()
            .map(|(i, (txs, sigs))| prove_group(&gc, bid, i as u64, txs, sigs))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let first = bc.step(bid, &proofs[0], None)?;
        let second = bc.step(bid, &proofs[1], Some(&first))?;
        bc.data.verify(second.clone())?;
        assert_eq!(second.public_inputs[BPI_NUM_GROUPS].to_canonical_u64(), 2);
        assert!(bc.step(bid, &proofs[2], Some(&second)).is_err());
        let mut overflow = PartialWitness::new();
        overflow.set_bool_target(bc.condition, true);
        overflow.set_hash_target(bc.block_id, bid);
        overflow.set_proof_with_pis_target(&bc.group_pts[0], &proofs[2]);
        overflow.set_proof_with_pis_target(&bc.inner, &second);
        overflow.set_verifier_data_target(&bc.verifier_data_target, &bc.data.verifier_only);
        assert!(rejected_witness(&bc.data, overflow));

        let mut previous = None;
        let mut tip = genesis;
        for height in 1..=3 {
            let block = make_block(0xCA91 + height, 1, 1);
            let bid = block_id(height, tip, block.tx_root);
            let gp = prove_group(&gc, bid, 0, &block.groups[0], &block.sigs[0])?;
            let bp = bc.step(bid, &gp, None)?;
            if height <= 2 {
                let proof = cc.step(genesis, height, tip, &bp, previous.as_ref())?;
                let (actual_height, _, actual_tip) = cc.verify_chain(&proof, genesis)?;
                assert_eq!(actual_height, height);
                tip = actual_tip;
                previous = Some(proof);
            } else {
                assert!(cc.step(genesis, height, tip, &bp, previous.as_ref()).is_err());
                let mut overflow = PartialWitness::new();
                overflow.set_bool_target(cc.condition, true);
                overflow.set_hash_target(cc.genesis, genesis);
                overflow.set_target(cc.height, F::from_canonical_u64(height));
                overflow.set_hash_target(cc.prev_hash, tip);
                overflow.set_proof_with_pis_target(&cc.block_pt, &bp);
                overflow.set_proof_with_pis_target(&cc.inner, previous.as_ref().unwrap());
                overflow.set_verifier_data_target(&cc.verifier_data_target(), &cc.data.verifier_only);
                assert!(rejected_witness(&cc.data, overflow));
            }
        }
        Ok(())
    }

    #[test]
    fn digits_match_wots_parameters() {
        let msg = HashOut { elements: [F::from_canonical_u64(7); 4] };
        let d = digits_of(msg);
        assert_eq!(d.len(), L);
        assert!(d.iter().all(|&x| x < W));
        let c: usize = d[..N_MSG_DIGITS].iter().map(|&x| WM1 - x).sum();
        let enc = d[N_MSG_DIGITS] + W * d[N_MSG_DIGITS + 1] + W * W * d[N_MSG_DIGITS + 2];
        assert_eq!(c, enc, "checksum digits must encode the checksum");
    }

    #[test]
    fn native_block_commitment_is_order_sensitive() {
        let bb = make_block(1, 4, 2);
        let mut swapped = bb.groups.clone();
        swapped.swap(0, 1);
        assert_ne!(tx_root(&bb.groups, 2), tx_root(&swapped, 2));
    }

    #[test]
    fn padding_group_differs_from_full_group() {
        let bb = make_block(2, 3, 2);
        assert_ne!(group_digest(&bb.groups[1], 2), group_digest(&bb.groups[0], 2));
    }

    #[test]
    #[should_panic(expected = "transaction count exceeds XMSS tree capacity")]
    fn xmss_block_builder_refuses_one_time_key_reuse() {
        let _ = make_xmss_block(3, 3, 2, 1);
    }

    #[test]
    fn xmss_blocks_share_one_root_and_consume_disjoint_indices() {
        let tree = wots_poseidon::xmss_keygen(3, 2, L);
        let first = make_xmss_block_from_tree(&tree, 0, 2, 2, 10);
        let second = make_xmss_block_from_tree(&tree, 2, 2, 2, 11);
        let blocks: Vec<Vec<Tx>> = vec![
            first.groups.iter().flatten().copied().collect(),
            second.groups.iter().flatten().copied().collect(),
        ];

        assert!(blocks.iter().flatten().all(|tx| tx.pk == tree.root));
        assert_eq!(
            blocks.iter().flatten().map(|tx| tx.index).collect::<Vec<_>>(),
            vec![0, 1, 2, 3]
        );
        assert!(detect_index_reuse(&blocks).is_empty());
    }

    #[test]
    #[ignore = "builds and proves the recursive group, block and chain circuits"]
    fn fan_in_two_matches_sequential_block_and_enters_the_chain() -> anyhow::Result<()> {
        let group_budget = 2;
        let block = make_block(0xBA7C_0002, 5, group_budget);
        let genesis = zero_hash();
        let bid = block_id(1, genesis, block.tx_root);
        let gc = build_group_circuit(group_budget);
        let group_proofs = block
            .groups
            .iter()
            .zip(&block.sigs)
            .enumerate()
            .map(|(index, (group, signatures))| {
                prove_group(&gc, bid, index as u64, group, signatures)
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        let sequential = build_block_circuit(&gc);
        let mut sequential_proof = None;
        for proof in &group_proofs {
            sequential_proof = Some(sequential.step(bid, proof, sequential_proof.as_ref())?);
        }
        let sequential_proof = sequential_proof.expect("non-empty block");
        sequential.verify_block(
            &sequential_proof,
            bid,
            block.tx_root,
            block.groups.len() as u64,
            block.num_txs,
        )?;

        let batched = build_block_circuit_with_fan_in(&gc, 2);
        for (condition, active, second) in [(0, 0, 1), (0, 2, 0), (2, 0, 0)] {
            let mut witness = PartialWitness::new();
            witness.set_target(batched.condition.target, F::from_canonical_u64(condition));
            witness.set_target(batched.additional_group_active[0].target, F::from_canonical_u64(active));
            witness.set_hash_target(batched.block_id, bid);
            witness.set_proof_with_pis_target(&batched.group_pts[0], &group_proofs[0]);
            witness.set_proof_with_pis_target(&batched.group_pts[1], &group_proofs[second]);
            witness.set_proof_with_pis_target(&batched.inner, &batched.base_proof);
            witness.set_verifier_data_target(&batched.verifier_data_target, &batched.data.verifier_only);
            assert!(rejected_witness(&batched.data, witness));
        }
        assert!(
            batched
                .step_batch(
                    bid,
                    &[group_proofs[1].clone(), group_proofs[0].clone()],
                    None,
                )
                .is_err(),
            "a batched step must reject reordered group indices"
        );
        assert!(
            batched
                .step_batch(
                    bid,
                    &[group_proofs[0].clone(), group_proofs[0].clone()],
                    None,
                )
                .is_err(),
            "a batched step must reject a duplicated group index"
        );
        assert!(
            batched.step_batch(bid, &group_proofs, None).is_err(),
            "the host API must reject a batch larger than the fixed fan-in"
        );
        assert!(
            batched
                .step_batch_with_padding(
                    bid,
                    std::slice::from_ref(&group_proofs[0]),
                    None,
                    &group_proofs[1],
                )
                .is_err(),
            "an inactive slot must repeat the first slot's public statement"
        );
        let mut batched_proof = None;
        for proofs in group_proofs.chunks(2) {
            batched_proof = Some(batched.step_batch(bid, proofs, batched_proof.as_ref())?);
        }
        let batched_proof = batched_proof.expect("non-empty block");
        batched.verify_block(
            &batched_proof,
            bid,
            block.tx_root,
            block.groups.len() as u64,
            block.num_txs,
        )?;
        assert_eq!(
            &sequential_proof.public_inputs[..BLOCK_NUM_PI_LOGICAL],
            &batched_proof.public_inputs[..BLOCK_NUM_PI_LOGICAL]
        );

        let chain = build_chain_circuit(&batched, &gc);
        let chain_proof = chain.step(genesis, 1, genesis, &batched_proof, None)?;
        let (height, _, _) = chain.verify_chain(&chain_proof, genesis)?;
        assert_eq!(height, 1);
        Ok(())
    }
}
