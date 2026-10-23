use std::io::Write;
use std::path::Path;
use std::time::Instant;

use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOut;
use plonky2::plonk::proof::ProofWithPublicInputs;

use crate::pcc::{
    build_chain_circuit, fold_chain, tip_hash, BlockCircuit, ChainCircuit, GroupCircuit,
    C, D, F, MAX_CHAIN_BLOCKS,
};

type Proof = ProofWithPublicInputs<F, C, D>;

pub struct ChainRun {
    circuit: ChainCircuit,
    predecessor: Option<Proof>,
    pub genesis: HashOut<F>,
    pub height: u64,
    pub previous_tip: HashOut<F>,
    previous_commitment: HashOut<F>,
}

pub struct ChainMeasurement {
    pub prove_ms: f64,
    pub verify_ms: f64,
    pub persist_ms: f64,
    pub proof_bytes: usize,
    pub commitment: HashOut<F>,
    pub tip: HashOut<F>,
}

pub fn validate_height(height: u64, predecessor_height: Option<u64>) -> anyhow::Result<()> {
    anyhow::ensure!((1..=MAX_CHAIN_BLOCKS).contains(&height), "invalid chain height");
    let expected = predecessor_height.unwrap_or(0).checked_add(1);
    anyhow::ensure!(expected == Some(height), "predecessor height mismatch");
    Ok(())
}

impl ChainRun {
    pub fn new(
        bc: &BlockCircuit,
        gc: &GroupCircuit,
        predecessor_path: Option<&Path>,
        height: u64,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!((1..=MAX_CHAIN_BLOCKS).contains(&height), "invalid chain height");
        anyhow::ensure!(predecessor_path.is_some() == (height > 1), "missing or extraneous predecessor");
        let circuit = build_chain_circuit(bc, gc);
        let genesis = HashOut { elements: [F::from_canonical_u64(0xACE0); 4] };
        let predecessor = if let Some(path) = predecessor_path {
            anyhow::ensure!(std::fs::metadata(path)?.len() <= 16 * 1024 * 1024, "oversized predecessor");
            Some(Proof::from_bytes(std::fs::read(path)?, &circuit.data.common)?)
        } else {
            None
        };
        let (previous_tip, previous_commitment) = if let Some(proof) = &predecessor {
            let (previous_height, commitment, tip) = circuit.verify_chain(proof, genesis)?;
            validate_height(height, Some(previous_height))?;
            (tip, commitment)
        } else {
            validate_height(height, None)?;
            (genesis, genesis)
        };
        Ok(Self { circuit, predecessor, genesis, height, previous_tip, previous_commitment })
    }

    pub fn finish(
        &self,
        block_proof: &Proof,
        bid: HashOut<F>,
        root: HashOut<F>,
        groups: u64,
        transactions: u64,
        destination: &Path,
    ) -> anyhow::Result<ChainMeasurement> {
        anyhow::ensure!(!destination.exists(), "chain output already exists");
        let start = Instant::now();
        let proof = self.circuit.step(
            self.genesis, self.height, self.previous_tip, block_proof, self.predecessor.as_ref(),
        )?;
        let prove_ms = start.elapsed().as_secs_f64() * 1000.0;
        let start = Instant::now();
        let (height, commitment, tip) = self.circuit.verify_chain(&proof, self.genesis)?;
        anyhow::ensure!(height == self.height, "final chain height mismatch");
        anyhow::ensure!(tip == tip_hash(bid, root, groups, transactions), "final chain tip mismatch");
        anyhow::ensure!(commitment == fold_chain(self.previous_commitment, tip), "chain fold mismatch");
        let verify_ms = start.elapsed().as_secs_f64() * 1000.0;
        let start = Instant::now();
        let bytes = proof.to_bytes();
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(destination)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        let persist_ms = start.elapsed().as_secs_f64() * 1000.0;
        Ok(ChainMeasurement { prove_ms, verify_ms, persist_ms, proof_bytes: bytes.len(), commitment, tip })
    }
}

#[cfg(test)]
mod tests {
    use super::{validate_height, MAX_CHAIN_BLOCKS};

    #[test]
    fn extension_requires_exact_predecessor_height() {
        assert!(validate_height(1, None).is_ok());
        assert!(validate_height(2, Some(1)).is_ok());
        assert!(validate_height(MAX_CHAIN_BLOCKS, Some(MAX_CHAIN_BLOCKS - 1)).is_ok());
        for (height, prev) in [(0, None), (2, None), (1, Some(1)), (3, Some(1)),
                               (MAX_CHAIN_BLOCKS + 1, Some(MAX_CHAIN_BLOCKS)), (1, Some(u64::MAX))] {
            assert!(validate_height(height, prev).is_err());
        }
    }
}
