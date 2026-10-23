use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

use anyhow::{ensure, Result};
use pcb_recursive::pcc::*;
use pcb_recursive::public_history::{decode_with_endpoint, encode, reconstruct, PublicBlock};
use plonky2::plonk::proof::ProofWithPublicInputs;

fn ms(start: Instant) -> f64 { start.elapsed().as_secs_f64() * 1000.0 }

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    ensure!(args.len() == 6, "usage: pcb_history_bench out blocks k g repetitions");
    let out = PathBuf::from(&args[1]);
    ensure!(!out.exists(), "output already exists");
    let blocks: usize = args[2].parse()?;
    let k: usize = args[3].parse()?;
    let g: usize = args[4].parse()?;
    let repetitions: usize = args[5].parse()?;
    ensure!(blocks > 0 && blocks <= 128 && k > 0 && k <= 1024 && g > 0 && g <= 16 && repetitions > 0,
            "invalid benchmark size");
    std::fs::create_dir_all(&out)?;
    let gc = build_group_circuit(g);
    let bc = build_block_circuit(&gc);
    let cc = build_chain_circuit(&bc, &gc);
    let genesis = zero_hash();
    let mut tip = genesis;
    let mut chain = None;
    let mut history = Vec::new();
    let mut witnesses = Vec::new();
    let mut results = std::fs::File::create(out.join("timings.csv"))?;
    writeln!(results, "blocks,transactions,g,queries,rep,history_bytes,proof_bytes,proof_decode_ms,trusted_verify_ms,public_decode_and_reconstruct_ms,named_total_ms,native_replay_ms,verified")?;
    for height in 1..=blocks {
        let built = make_block(202609230000 + height as u64, k, g);
        let bid = block_id(height as u64, tip, built.tx_root);
        let mut aggregate = None;
        for (j, (txs, sigs)) in built.groups.iter().zip(&built.sigs).enumerate() {
            let group = prove_group(&gc, bid, j as u64, txs, sigs)?;
            gc.data.verify(group.clone())?;
            aggregate = Some(bc.step(bid, &group, aggregate.as_ref())?);
        }
        let aggregate = aggregate.unwrap();
        bc.verify_block(&aggregate, bid, built.tx_root, built.groups.len() as u64, k as u64)?;
        let proof = cc.step(genesis, height as u64, tip, &aggregate, chain.as_ref())?;
        history.push(PublicBlock { height: height as u64, predecessor: tip,
            occupancies: built.groups.iter().map(Vec::len).collect(),
            transactions: built.groups.iter().flatten().copied().collect() });
        witnesses.extend(built.groups.iter().flatten().copied().zip(built.sigs.iter().flatten().cloned()));
        let expected = reconstruct(&history, genesis, g, GroupMode::Wots)?;
        ensure!(cc.verify_chain(&proof, genesis)? == expected, "chain endpoint mismatch");
        tip = expected.2;
        chain = Some(proof);
        if !height.is_power_of_two() && height != blocks { continue; }
        let public = encode(&history, genesis, g, GroupMode::Wots)?;
        let proof_bytes = chain.as_ref().unwrap().to_bytes();
        std::fs::write(out.join(format!("h{height}.history")), &public)?;
        std::fs::write(out.join(format!("h{height}.proof")), &proof_bytes)?;
        for rep in 0..=repetitions {
            let native = || -> Result<f64> {
                let start = Instant::now();
                for (tx, signature) in &witnesses { ensure!(native_verify(tx, signature), "native replay failed"); }
                Ok(ms(start))
            };
            let first = if rep % 2 == 0 { Some(native()?) } else { None };
            let start = Instant::now();
            let parsed = ProofWithPublicInputs::<F, C, D>::from_bytes(proof_bytes.clone(), &cc.data.common)?;
            let decode_ms = ms(start);
            let start = Instant::now();
            ensure!(cc.verify_chain(&parsed, genesis)? == expected, "trusted endpoint mismatch");
            let verify_ms = ms(start);
            let all = Instant::now();
            let parse = Instant::now();
            let (_decoded, named) = decode_with_endpoint(&public, genesis, g, GroupMode::Wots)?;
            let public_ms = ms(parse);
            let parsed = ProofWithPublicInputs::<F, C, D>::from_bytes(proof_bytes.clone(), &cc.data.common)?;
            ensure!(cc.verify_chain(&parsed, genesis)? == named, "named endpoint mismatch");
            let named_ms = ms(all);
            let native_ms = match first { Some(value) => value, None => native()? };
            if rep > 0 {
                writeln!(results, "{height},{},{g},{},{rep},{},{},{decode_ms:.6},{verify_ms:.6},{public_ms:.6},{named_ms:.6},{native_ms:.6},true",
                    height*k, deployment_query_rounds(), public.len(), proof_bytes.len())?;
            }
        }
        let mut changed = history.clone();
        changed.last_mut().unwrap().transactions[0].msg = zero_hash();
        ensure!(reconstruct(&changed, genesis, g, GroupMode::Wots)? != expected, "mutation did not change endpoint");
        results.flush()?;
        eprintln!("verified and timed named history at {height} blocks");
    }
    Ok(())
}
