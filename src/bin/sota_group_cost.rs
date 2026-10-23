use std::time::Instant;

use pcb_recursive::mem::peak_working_set_mb;
use pcb_recursive::pcc::{
    block_id, build_group_circuit_with_queries, make_block, prove_group, zero_hash,
};
use plonky2::field::types::PrimeField64;

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

fn mean(values: &[f64]) -> f64 {
    values.iter().sum::<f64>() / values.len() as f64
}

fn samples(values: &[f64]) -> String {
    values
        .iter()
        .map(|value| format!("{value:.3}"))
        .collect::<Vec<_>>()
        .join("|")
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let signatures: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(1);
    let repetitions: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(5);
    let query_rounds: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(28);

    anyhow::ensure!(signatures > 0, "signature count must be positive");
    anyhow::ensure!(repetitions > 0, "at least one repetition is required");
    anyhow::ensure!(query_rounds > 0, "FRI query count must be positive");

    let build_start = Instant::now();
    let circuit = build_group_circuit_with_queries(signatures, query_rounds);
    let build_ms = build_start.elapsed().as_secs_f64() * 1000.0;
    let circuit_id = circuit
        .circuit_id
        .elements
        .iter()
        .map(|element| format!("{:016x}", element.to_canonical_u64()))
        .collect::<String>();

    let block = make_block(0x50_54_41_42 + signatures as u64, signatures, signatures);
    let block_digest = block_id(1, zero_hash(), block.tx_root);

    let warmup = prove_group(
        &circuit,
        block_digest,
        0,
        &block.groups[0],
        &block.sigs[0],
    )?;
    circuit.data.verify(warmup)?;

    let mut prove_ms = Vec::with_capacity(repetitions);
    let mut verify_ms = Vec::with_capacity(repetitions);
    let mut proof_bytes = 0usize;
    let mut peak_mb = peak_working_set_mb();

    for _ in 0..repetitions {
        let prove_start = Instant::now();
        let proof = prove_group(
            &circuit,
            block_digest,
            0,
            &block.groups[0],
            &block.sigs[0],
        )?;
        prove_ms.push(prove_start.elapsed().as_secs_f64() * 1000.0);
        peak_mb = peak_mb.max(peak_working_set_mb());
        proof_bytes = proof.to_bytes().len();

        let verify_start = Instant::now();
        circuit.data.verify(proof)?;
        verify_ms.push(verify_start.elapsed().as_secs_f64() * 1000.0);
    }

    let fri = &circuit.data.common.config.fri_config;
    let conjectured_bits =
        query_rounds * fri.rate_bits + fri.proof_of_work_bits as usize;

    println!(
        "signatures,query_rounds,rate_bits,pow_bits,conjectured_bits,circuit_id,build_ms,prove_median_ms,prove_mean_ms,prove_iqr_ms,verify_median_ms,verify_mean_ms,verify_iqr_ms,proof_bytes,peak_mb,repetitions,prove_samples_ms,verify_samples_ms"
    );
    println!(
        "{signatures},{query_rounds},{},{},{conjectured_bits},{circuit_id},{build_ms:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{proof_bytes},{peak_mb:.0},{repetitions},\"{}\",\"{}\"",
        fri.rate_bits,
        fri.proof_of_work_bits,
        median(&prove_ms),
        mean(&prove_ms),
        iqr(&prove_ms),
        median(&verify_ms),
        mean(&verify_ms),
        iqr(&verify_ms),
        samples(&prove_ms),
        samples(&verify_ms),
    );

    Ok(())
}
