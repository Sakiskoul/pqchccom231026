use std::time::Instant;
use anyhow::{ensure, Result};
use pcb_recursive::pcc::*;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    ensure!(args.len() == 3, "usage: pcb_binding_bench g repetitions");
    let g: usize = args[1].parse()?;
    let reps: usize = args[2].parse()?;
    ensure!((1..=16).contains(&g) && reps > 0, "invalid probe parameters");
    let queries = deployment_query_rounds();
    let plain = binding_probe::build(g, queries, false);
    let bound = binding_probe::build(g, queries, true);
    ensure!(plain.data.common.num_public_inputs == bound.data.common.num_public_inputs, "unmatched input width");
    println!("g,queries,rep,seed,position,bind,gates,degree,public_inputs,prove_ms,verify_ms,proof_bytes,verified");
    for rep in 0..=reps {
        let seed = 202609230100 + rep as u64;
        let block = make_block(seed, g, g);
        let order = if rep % 2 == 0 { [false, true] } else { [true, false] };
        for (position, bind) in order.into_iter().enumerate() {
            let circuit = if bind { &bound } else { &plain };
            let start = Instant::now();
            let proof = circuit.prove(&block.groups[0], &block.sigs[0])?;
            let prove_ms = start.elapsed().as_secs_f64() * 1000.0;
            let start = Instant::now();
            circuit.data.verify(proof.clone())?;
            let verify_ms = start.elapsed().as_secs_f64() * 1000.0;
            let expected: Vec<_> = block.groups[0].iter().flat_map(|tx| tx.pk.elements.into_iter().chain(tx.msg.elements)).collect();
            ensure!(proof.public_inputs[..expected.len()] == expected, "tuple mismatch");
            if rep > 0 {
                println!("{g},{queries},{rep},{seed},{position},{bind},{},{},{},{prove_ms:.6},{verify_ms:.6},{},true",
                    circuit.gates, circuit.data.common.degree_bits(), circuit.data.common.num_public_inputs, proof.to_bytes().len());
            }
        }
    }
    Ok(())
}
