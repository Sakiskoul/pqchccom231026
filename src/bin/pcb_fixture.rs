use std::io::Write;

use pcb_recursive::pcc::make_block;
use plonky2::field::types::PrimeField64;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    anyhow::ensure!(args.len() == 4, "usage: pcb_fixture TRANSACTIONS SEED OUTPUT");
    let n: usize = args[1].parse()?;
    let seed: u64 = args[2].parse()?;
    anyhow::ensure!((1..=1024).contains(&n), "invalid fixture size");
    let block = make_block(seed, n, 4);
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&args[3])?;
    for tx in block.groups.iter().flatten() {
        for element in tx.msg.elements {
            file.write_all(&element.to_canonical_u64().to_le_bytes())?;
        }
    }
    file.sync_all()?;
    Ok(())
}
