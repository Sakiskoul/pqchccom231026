use std::time::Instant;

use pcb_recursive::mem::peak_working_set_mb;
use pcb_recursive::pcc::{
    block_id, build_block_circuit, build_chain_circuit, build_group_circuit, make_block,
    prove_group, tip_hash, zero_hash, F,
};
use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOut;

fn median(v: &mut [f64]) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len();
    if n == 0 {
        return 0.0;
    }
    if n % 2 == 1 { v[n / 2] } else { (v[n / 2 - 1] + v[n / 2]) / 2.0 }
}

fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().collect();
    let blocks: usize = a.get(1).and_then(|s| s.parse().ok()).unwrap_or(8);
    let k: usize = a.get(2).and_then(|s| s.parse().ok()).unwrap_or(4);
    let g: usize = a.get(3).and_then(|s| s.parse().ok()).unwrap_or(2);
    let reps: usize = a.get(4).and_then(|s| s.parse().ok()).unwrap_or(5);

    eprintln!("building circuits (group budget G={g}) ...");
    let t = Instant::now();
    let gc = build_group_circuit(g);
    let bc = build_block_circuit(&gc);
    let cc = build_chain_circuit(&bc, &gc);
    eprintln!(
        "  group 2^{} gates, block 2^{} gates, chain 2^{} gates  ({:.1}s)",
        gc.data.common.degree_bits(),
        bc.data.common.degree_bits(),
        cc.data.common.degree_bits(),
        t.elapsed().as_secs_f64()
    );

    let genesis = HashOut { elements: [F::from_canonical_u64(0xACE0); 4] };
    let mut prev_hash = genesis;
    let mut chain_proof = None;

    println!("blocks,txs_total,txs_per_block,group_budget,groups_per_block,proof_events_total,group_proof_bytes,block_proof_bytes,chain_proof_bytes,group_prove_ms,block_step_ms,chain_step_ms,block_total_ms,chain_verify_ms,peak_mb,cum_prove_s,public_inputs");

    let mut cum_prove = 0.0f64;
    let mut total_txs = 0u64;
    let mut proof_events_total = 0usize;

    for h in 1..=blocks {
        let bb = make_block(0x5EED + h as u64, k, g);
        total_txs += bb.num_txs;
        proof_events_total += 2 * bb.groups.len() + 1;
        let bid = block_id(h as u64, prev_hash, bb.tx_root);

        let mut group_proofs = Vec::with_capacity(bb.groups.len());
        let t0 = Instant::now();
        for (j, (txs, sigs)) in bb.groups.iter().zip(bb.sigs.iter()).enumerate() {
            let p = prove_group(&gc, bid, j as u64, txs, sigs)?;
            gc.data.verify(p.clone())?;
            group_proofs.push(p);
        }
        let group_ms = t0.elapsed().as_secs_f64() * 1000.0;
        let gp_bytes = group_proofs[0].to_bytes().len();

        let t1 = Instant::now();
        let mut block_proof = None;
        for gp in &group_proofs {
            block_proof = Some(bc.step(bid, gp, block_proof.as_ref())?);
        }
        let block_ms = t1.elapsed().as_secs_f64() * 1000.0;
        let block_proof = block_proof.expect("block must contain a group");
        let acc = bb.tx_root;
        bc.verify_block(&block_proof, bid, acc, bb.groups.len() as u64, bb.num_txs)?;
        let bp_bytes = block_proof.to_bytes().len();

        let t2 = Instant::now();
        let next = cc.step(genesis, h as u64, prev_hash, &block_proof, chain_proof.as_ref())?;
        let chain_ms = t2.elapsed().as_secs_f64() * 1000.0;

        let mut vt: Vec<f64> = Vec::with_capacity(reps);
        for _ in 0..reps {
            let tv = Instant::now();
            let (hh, _, _) = cc.verify_chain(&next, genesis)?;
            assert_eq!(hh, h as u64);
            vt.push(tv.elapsed().as_secs_f64() * 1000.0);
        }
        let verify_ms = median(&mut vt);

        prev_hash = tip_hash(bid, acc, bb.groups.len() as u64, bb.num_txs);
        let cp_bytes = next.to_bytes().len();
        let npi = next.public_inputs.len();
        chain_proof = Some(next);
        cum_prove += (group_ms + block_ms + chain_ms) / 1000.0;

        if h == 1 || h.is_power_of_two() || h == blocks {
            println!(
                "{h},{total_txs},{k},{g},{},{proof_events_total},{gp_bytes},{bp_bytes},{cp_bytes},{group_ms:.1},{block_ms:.1},{chain_ms:.1},{:.1},{verify_ms:.3},{:.0},{cum_prove:.1},{npi}",
                bb.groups.len(),
                group_ms + block_ms,
                peak_working_set_mb()
            );
        }
    }

    let final_proof = chain_proof.unwrap();
    let (h, commit, tip) = cc.verify_chain(&final_proof, genesis)?;
    eprintln!("final height {h}, chain commitment {commit:?}, tip {tip:?}");
    let _ = zero_hash();
    Ok(())
}
