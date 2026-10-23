use std::io::Write;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Instant;

use anyhow::{ensure, Result};
use pcb_recursive::pcc::*;
use pcb_recursive::public_history::decode_with_endpoint;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOut;
use plonky2::plonk::proof::ProofWithPublicInputs;

type Witness = (Tx, Vec<HashOut<F>>);

fn elapsed_ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

fn serial(batch: &[Witness]) -> bool {
    batch.iter().all(|(tx, signature)| native_verify(tx, signature))
}

fn with_native_pool<T>(batch: &[Witness], run: impl FnOnce(&dyn Fn() -> Result<bool>) -> Result<T>) -> Result<T> {
    ensure!(batch.len() >= 2, "two-worker replay requires at least two signatures");
    std::thread::scope(|scope| {
        let (done, completed) = mpsc::channel();
        let mut jobs = Vec::new();
        for chunk in batch.chunks(batch.len().div_ceil(2)) {
            let (sender, receiver) = mpsc::sync_channel::<()>(0);
            jobs.push(sender);
            let done = done.clone();
            scope.spawn(move || {
                while receiver.recv().is_ok() {
                    if done.send(serial(chunk)).is_err() { break; }
                }
            });
        }
        drop(done);
        let parallel = || -> Result<bool> {
            for worker in &jobs { worker.send(())?; }
            let a = completed.recv()?;
            let b = completed.recv()?;
            Ok(a && b)
        };
        run(&parallel)
    })
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    ensure!(args.len() == 4, "usage: pcb_replay_bench history_dir output_csv repetitions");
    let input = PathBuf::from(&args[1]);
    let output = PathBuf::from(&args[2]);
    let repetitions: usize = args[3].parse()?;
    ensure!(repetitions >= 6 && repetitions % 6 == 0, "complete six-order cycles required");
    ensure!(deployment_query_rounds() == 76, "this control uses the 76-query history");
    let gc = build_group_circuit(4);
    let bc = build_block_circuit(&gc);
    let cc = build_chain_circuit(&bc, &gc);
    let mut csv = std::fs::OpenOptions::new().write(true).create_new(true).open(output)?;
    writeln!(csv, "blocks,transactions,g,queries,rep,order,history_bytes,proof_bytes,public_ms,proof_decode_ms,proof_verify_ms,named_ms,serial_ms,parallel_ms,workers,verified")?;
    let orders = [[0,1,2], [0,2,1], [1,0,2], [1,2,0], [2,0,1], [2,1,0]];
    for height in [1usize, 2, 4, 8, 16] {
        let history = std::fs::read(input.join(format!("h{height}.history")))?;
        let proof_bytes = std::fs::read(input.join(format!("h{height}.proof")))?;
        let (blocks, endpoint) = decode_with_endpoint(&history, zero_hash(), 4, GroupMode::Wots)?;
        let mut witnesses = Vec::new();
        ensure!(blocks.len() == height, "unexpected history height");
        for (i, block) in blocks.iter().enumerate() {
            let generated = make_block(202609230000 + i as u64 + 1, 16, 4);
            let tuples: Vec<_> = generated.groups.iter().flatten().copied().collect();
            ensure!(block.transactions == tuples && block.occupancies == vec![4; 4], "fixture differs from persisted history");
            witnesses.extend(tuples.into_iter().zip(generated.sigs.into_iter().flatten()));
        }
        let proof = ProofWithPublicInputs::<F, C, D>::from_bytes(proof_bytes.clone(), &cc.data.common)?;
        ensure!(cc.verify_chain(&proof, zero_hash())? == endpoint, "persisted proof endpoint mismatch");
        with_native_pool(&witnesses, |parallel| {
            for rep in 0..=repetitions {
                let order = orders[rep.saturating_sub(1) % orders.len()];
                let mut times = [0.0; 3];
                let mut components = [0.0; 3];
                for mode in order {
                    let start = Instant::now();
                    match mode {
                        0 => ensure!(serial(&witnesses), "serial native rejection"),
                        1 => ensure!(parallel()?, "parallel native rejection"),
                        _ => {
                            let part = Instant::now();
                            let (_, expected) = decode_with_endpoint(&history, zero_hash(), 4, GroupMode::Wots)?;
                            components[0] = elapsed_ms(part);
                            let part = Instant::now();
                            let proof = ProofWithPublicInputs::<F, C, D>::from_bytes(proof_bytes.clone(), &cc.data.common)?;
                            components[1] = elapsed_ms(part);
                            let part = Instant::now();
                            ensure!(cc.verify_chain(&proof, zero_hash())? == expected, "named-history rejection");
                            components[2] = elapsed_ms(part);
                        }
                    }
                    times[mode] = elapsed_ms(start);
                }
                if rep > 0 {
                    writeln!(csv, "{height},{},4,76,{rep},{}-{}-{},{},{},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},2,true",
                        height*16, order[0], order[1], order[2], history.len(), proof_bytes.len(),
                        components[0], components[1], components[2], times[2], times[0], times[1])?;
                }
            }
            Ok(())
        })?;
        let mut corrupted = witnesses.clone();
        corrupted[0].1[0].elements[0] += F::ONE;
        ensure!(!serial(&corrupted), "serial accepted altered signature");
        with_native_pool(&corrupted, |parallel| {
            ensure!(!parallel()?, "parallel accepted altered signature");
            Ok(())
        })?;
        csv.flush()?;
        eprintln!("replay height={height} repetitions={repetitions} verified; altered signature rejected by both native paths");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistent_pool_matches_serial_and_rejects_corruption() -> Result<()> {
        let fixture = make_block(21, 16, 4);
        let mut batch: Vec<Witness> = fixture.groups.into_iter().flatten().zip(fixture.sigs.into_iter().flatten()).collect();
        with_native_pool(&batch, |parallel| {
            for _ in 0..3 { ensure!(serial(&batch) && parallel()?, "valid batch rejected"); }
            Ok(())
        })?;
        batch[8].1[0].elements[0] += F::ONE;
        with_native_pool(&batch, |parallel| {
            ensure!(!serial(&batch) && !parallel()?, "altered batch accepted");
            Ok(())
        })
    }
}
