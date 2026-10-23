use std::time::Instant;

use pcb_recursive::mem::peak_working_set_mb;
use pcb_recursive::pcc::{
    block_id, build_block_circuit, build_chain_circuit, build_group_circuit_with_queries,
    make_block, prove_group, F,
};
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::hash_types::HashOut;

fn median(values: &[f64]) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = sorted.len();
    if n % 2 == 1 {
        sorted[n / 2]
    } else {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    }
}

fn iqr(values: &[f64]) -> f64 {
    if values.len() < 4 {
        return 0.0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    sorted[3 * sorted.len() / 4] - sorted[sorted.len() / 4]
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let queries: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(28);
    let reps: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(5);
    let groups_per_block: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(4);
    let chain_blocks: usize = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(128);
    let group_budget: usize = args.get(5).and_then(|s| s.parse().ok()).unwrap_or(4);
    anyhow::ensure!(reps > 0, "at least one repetition is required");
    anyhow::ensure!(groups_per_block > 0, "groups per block must be positive");
    anyhow::ensure!(chain_blocks > 0, "chain length must be positive");
    anyhow::ensure!(group_budget > 0, "group budget must be positive");
    anyhow::ensure!(
        queries * 3 + 16 >= 100,
        "query budget does not meet Plonky2's configured 100-bit FRI target"
    );

    let build_start = Instant::now();
    let gc = build_group_circuit_with_queries(group_budget, queries);
    let bc = build_block_circuit(&gc);
    let cc = build_chain_circuit(&bc, &gc);
    let build_ms = build_start.elapsed().as_secs_f64() * 1000.0;

    anyhow::ensure!(
        gc.data.common.config.fri_config.num_query_rounds == queries
            && bc.data.common.config.fri_config.num_query_rounds == queries
            && cc.data.common.config.fri_config.num_query_rounds == queries,
        "query budget was not propagated through every recursive layer"
    );

    let block = make_block(0xF121_0000 + queries as u64, group_budget, group_budget);
    let genesis = HashOut {
        elements: [F::from_canonical_u64(0xACE0); 4],
    };
    let bid = block_id(1, genesis, block.tx_root);

    let warm_group = prove_group(&gc, bid, 0, &block.groups[0], &block.sigs[0])?;
    gc.data.verify(warm_group)?;
    let mut group_prove = Vec::with_capacity(reps);
    let mut group_proof = None;
    for _ in 0..reps {
        let start = Instant::now();
        let proof = prove_group(&gc, bid, 0, &block.groups[0], &block.sigs[0])?;
        group_prove.push(start.elapsed().as_secs_f64() * 1000.0);
        group_proof = Some(proof);
    }
    let group_proof = group_proof.unwrap();
    let mut group_verify = Vec::with_capacity(reps);
    for _ in 0..reps {
        let start = Instant::now();
        gc.data.verify(group_proof.clone())?;
        group_verify.push(start.elapsed().as_secs_f64() * 1000.0);
    }

    let warm_block = bc.step(bid, &group_proof, None)?;
    bc.verify_block(&warm_block, bid, block.tx_root, 1, group_budget as u64)?;
    let mut block_prove = Vec::with_capacity(reps);
    let mut block_proof = None;
    for _ in 0..reps {
        let start = Instant::now();
        let proof = bc.step(bid, &group_proof, None)?;
        block_prove.push(start.elapsed().as_secs_f64() * 1000.0);
        block_proof = Some(proof);
    }
    let block_proof = block_proof.unwrap();
    let mut block_verify = Vec::with_capacity(reps);
    for _ in 0..reps {
        let start = Instant::now();
        bc.verify_block(&block_proof, bid, block.tx_root, 1, group_budget as u64)?;
        block_verify.push(start.elapsed().as_secs_f64() * 1000.0);
    }

    let warm_chain = cc.step(genesis, 1, genesis, &block_proof, None)?;
    cc.verify_chain(&warm_chain, genesis)?;
    let mut chain_prove = Vec::with_capacity(reps);
    let mut chain_proof = None;
    for _ in 0..reps {
        let start = Instant::now();
        let proof = cc.step(genesis, 1, genesis, &block_proof, None)?;
        chain_prove.push(start.elapsed().as_secs_f64() * 1000.0);
        chain_proof = Some(proof);
    }
    let chain_proof = chain_proof.unwrap();
    let mut chain_verify = Vec::with_capacity(reps);
    for _ in 0..reps {
        let start = Instant::now();
        cc.verify_chain(&chain_proof, genesis)?;
        chain_verify.push(start.elapsed().as_secs_f64() * 1000.0);
    }

    let rate_bits = gc.data.common.config.fri_config.rate_bits;
    let pow_bits = gc.data.common.config.fri_config.proof_of_work_bits as f64;
    let lambda_conjectured = queries as f64 * rate_bits as f64 + pow_bits;
    let lambda_unique = 0.5 * queries as f64 * rate_bits as f64 + pow_bits;
    let block_events = 2.0 * groups_per_block as f64;
    let chain_events = (2 * groups_per_block + 1) as f64 * chain_blocks as f64;
    let circuit_id = gc
        .circuit_id
        .elements
        .iter()
        .map(|e| format!("{:016x}", e.to_canonical_u64()))
        .collect::<String>();

    println!(
        "query_rounds,rate_bits,pow_bits,reps,analysis_groups_per_block,analysis_chain_blocks,circuit_budget,occupancy,circuit_id,group_degree_bits,block_degree_bits,chain_degree_bits,build_ms,group_prove_ms,group_prove_iqr_ms,group_verify_ms,group_verify_iqr_ms,group_proof_bytes,block_step_ms,block_step_iqr_ms,block_verify_ms,block_verify_iqr_ms,block_proof_bytes,chain_step_ms,chain_step_iqr_ms,chain_verify_ms,chain_verify_iqr_ms,chain_proof_bytes,peak_mb,lambda_conjectured_bits,lambda_unique_bits,block_margin_conjectured_bits,block_margin_unique_bits,chain_margin_conjectured_bits,chain_margin_unique_bits"
    );
    println!(
        "{queries},{rate_bits},{pow_bits:.0},{reps},{groups_per_block},{chain_blocks},{group_budget},{group_budget},{circuit_id},{},{},{},{build_ms:.1},{:.1},{:.1},{:.3},{:.3},{},{:.1},{:.1},{:.3},{:.3},{},{:.1},{:.1},{:.3},{:.3},{},{:.0},{lambda_conjectured:.2},{lambda_unique:.2},{:.2},{:.2},{:.2},{:.2}",
        gc.data.common.degree_bits(),
        bc.data.common.degree_bits(),
        cc.data.common.degree_bits(),
        median(&group_prove),
        iqr(&group_prove),
        median(&group_verify),
        iqr(&group_verify),
        group_proof.to_bytes().len(),
        median(&block_prove),
        iqr(&block_prove),
        median(&block_verify),
        iqr(&block_verify),
        block_proof.to_bytes().len(),
        median(&chain_prove),
        iqr(&chain_prove),
        median(&chain_verify),
        iqr(&chain_verify),
        chain_proof.to_bytes().len(),
        peak_working_set_mb(),
        lambda_conjectured - block_events.log2(),
        lambda_unique - block_events.log2(),
        lambda_conjectured - chain_events.log2(),
        lambda_unique - chain_events.log2(),
    );
    Ok(())
}
