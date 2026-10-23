use anyhow::{ensure, Result};
use pcb_recursive::pcc::*;
use pcb_recursive::public_history::{decode_with_endpoint, reconstruct, PublicBlock};
use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOut;
use plonky2::plonk::proof::ProofWithPublicInputs;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    ensure!(args.len() >= 5, "usage: pcb_check_artifacts mode g [proof history | proof seed k height]...");
    let mode = &args[1];
    let g: usize = args[2].parse()?;
    ensure!([2, 4, 8].contains(&g), "unsupported campaign budget");
    let width = match mode.as_str() { "history" => 2, "chain" => 4, _ => anyhow::bail!("invalid mode") };
    ensure!((args.len()-3) % width == 0, "incomplete artifact arguments");
    let gc = build_group_circuit(g);
    let bc = build_block_circuit(&gc);
    let cc = build_chain_circuit(&bc, &gc);
    let mut count = 0;
    for record in args[3..].chunks(width) {
        let bytes = std::fs::read(&record[0])?;
        let proof = ProofWithPublicInputs::<F, C, D>::from_bytes(bytes, &cc.data.common)?;
        let (genesis, expected) = if mode == "history" {
            let genesis = zero_hash();
            let (_, endpoint) = decode_with_endpoint(&std::fs::read(&record[1])?, genesis, g, GroupMode::Wots)?;
            (genesis, endpoint)
        } else {
            let genesis = HashOut { elements: [F::from_canonical_u64(0xACE0); 4] };
            let seed: u64 = record[1].parse()?;
            let k: usize = record[2].parse()?;
            let height: usize = record[3].parse()?;
            ensure!((1..=2).contains(&height), "unexpected campaign height");
            let mut history = Vec::new();
            let mut tip = genesis;
            for h in 1..=height {
                let (seed, k) = if h < height { (202609234000, 8) } else { (seed, k) };
                let block = make_block(seed, k, g);
                history.push(PublicBlock { height: h as u64, predecessor: tip,
                    occupancies: block.groups.iter().map(Vec::len).collect(),
                    transactions: block.groups.into_iter().flatten().collect() });
                tip = reconstruct(&history, genesis, g, GroupMode::Wots)?.2;
            }
            (genesis, reconstruct(&history, genesis, g, GroupMode::Wots)?)
        };
        ensure!(cc.verify_chain(&proof, genesis)? == expected, "artifact differs from expected public history");
        count += 1;
    }
    println!("mode,g,queries,group_degree,block_degree,chain_degree,proofs_checked");
    println!("{mode},{g},{},{},{},{},{count}", deployment_query_rounds(), gc.data.common.degree_bits(),
        bc.data.common.degree_bits(), cc.data.common.degree_bits());
    Ok(())
}
