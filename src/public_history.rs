use anyhow::{ensure, Result};
use plonky2::field::types::{Field, Field64, PrimeField64};
use plonky2::hash::hash_types::HashOut;
use plonky2::plonk::proof::ProofWithPublicInputs;

use crate::pcc::{block_id, fold_acc, fold_chain, group_digest_mode, tip_hash, zero_hash,
    ChainCircuit, GroupMode, Tx, C, D, F, MAX_BLOCK_GROUPS, MAX_CHAIN_BLOCKS};

#[derive(Clone, Debug)]
pub struct PublicBlock {
    pub height: u64,
    pub predecessor: HashOut<F>,
    pub occupancies: Vec<usize>,
    pub transactions: Vec<Tx>,
}

impl PublicBlock {
    pub fn commitment(&self, budget: usize, mode: GroupMode) -> Result<HashOut<F>> {
        ensure!(budget > 0 && budget as u64 <= u32::MAX as u64 / MAX_BLOCK_GROUPS,
                "invalid deployment budget");
        ensure!((1..=MAX_CHAIN_BLOCKS).contains(&self.height), "invalid block height");
        ensure!(!self.occupancies.is_empty() && self.occupancies.len() <= MAX_BLOCK_GROUPS as usize,
                "invalid group count");
        let mut count = 0usize;
        for &n in &self.occupancies {
            ensure!(n > 0 && n <= budget, "invalid public occupancy");
            count = count.checked_add(n).ok_or_else(|| anyhow::anyhow!("transaction count overflow"))?;
        }
        ensure!(count == self.transactions.len(), "partition does not cover transaction list");
        for tx in &self.transactions {
            match mode {
                GroupMode::Wots => ensure!(tx.index == 0, "nonzero one-time index"),
                GroupMode::Xmss { height } => {
                    ensure!(height < 64 && tx.index < (1u64 << height), "invalid Merkle index");
                }
            }
        }
        let mut offset = 0;
        let mut root = zero_hash();
        for &n in &self.occupancies {
            root = fold_acc(root, group_digest_mode(&self.transactions[offset..offset+n], budget, mode));
            offset += n;
        }
        Ok(root)
    }
}

pub fn reconstruct(blocks: &[PublicBlock], genesis: HashOut<F>, budget: usize,
                   mode: GroupMode) -> Result<(u64, HashOut<F>, HashOut<F>)> {
    ensure!(!blocks.is_empty() && blocks.len() <= MAX_CHAIN_BLOCKS as usize, "invalid history length");
    let mut tip = genesis;
    let mut commitment = genesis;
    for (index, block) in blocks.iter().enumerate() {
        ensure!(block.height == index as u64 + 1, "nonconsecutive history");
        ensure!(block.predecessor == tip, "predecessor mismatch");
        let root = block.commitment(budget, mode)?;
        let bid = block_id(block.height, tip, root);
        tip = tip_hash(bid, root, block.occupancies.len() as u64, block.transactions.len() as u64);
        commitment = fold_chain(commitment, tip);
    }
    Ok((blocks.len() as u64, commitment, tip))
}

pub fn verify_named_history(circuit: &ChainCircuit, proof: &ProofWithPublicInputs<F, C, D>,
                            blocks: &[PublicBlock], genesis: HashOut<F>, budget: usize,
                            mode: GroupMode) -> Result<()> {
    let expected = reconstruct(blocks, genesis, budget, mode)?;
    ensure!(circuit.verify_chain(proof, genesis)? == expected, "named history differs from proof");
    Ok(())
}

pub fn encode(blocks: &[PublicBlock], genesis: HashOut<F>, budget: usize, mode: GroupMode) -> Result<Vec<u8>> {
    reconstruct(blocks, genesis, budget, mode)?;
    let mut bytes = Vec::new();
    fn integer(bytes: &mut Vec<u8>, x: u64) { bytes.extend_from_slice(&x.to_le_bytes()); }
    fn hash(bytes: &mut Vec<u8>, h: HashOut<F>) {
        for x in h.elements { integer(bytes, x.to_canonical_u64()); }
    }
    integer(&mut bytes, blocks.len() as u64);
    for block in blocks {
        integer(&mut bytes, block.height);
        hash(&mut bytes, block.predecessor);
        integer(&mut bytes, block.occupancies.len() as u64);
        integer(&mut bytes, block.transactions.len() as u64);
        for &n in &block.occupancies { integer(&mut bytes, n as u64); }
        for tx in &block.transactions {
            hash(&mut bytes, tx.pk);
            hash(&mut bytes, tx.msg);
            integer(&mut bytes, tx.index);
        }
    }
    Ok(bytes)
}

pub fn decode(bytes: &[u8], genesis: HashOut<F>, budget: usize, mode: GroupMode) -> Result<Vec<PublicBlock>> {
    Ok(decode_with_endpoint(bytes, genesis, budget, mode)?.0)
}

pub fn decode_with_endpoint(bytes: &[u8], genesis: HashOut<F>, budget: usize, mode: GroupMode)
    -> Result<(Vec<PublicBlock>, (u64, HashOut<F>, HashOut<F>))> {
    struct Reader<'a>(&'a [u8]);
    impl Reader<'_> {
        fn integer(&mut self) -> Result<u64> {
            ensure!(self.0.len() >= 8, "truncated history");
            let value = u64::from_le_bytes(self.0[..8].try_into()?);
            self.0 = &self.0[8..];
            Ok(value)
        }
        fn hash(&mut self) -> Result<HashOut<F>> {
            let mut elements = [F::ZERO; 4];
            for x in &mut elements {
                let value = self.integer()?;
                ensure!(value < F::ORDER, "noncanonical field encoding");
                *x = F::from_canonical_u64(value);
            }
            Ok(HashOut { elements })
        }
    }
    let mut reader = Reader(bytes);
    let count = reader.integer()?;
    ensure!((1..=MAX_CHAIN_BLOCKS).contains(&count), "invalid history length");
    ensure!(count <= reader.0.len() as u64 / 136, "history count exceeds payload");
    let mut blocks = Vec::new();
    for _ in 0..count {
        let height = reader.integer()?;
        let predecessor = reader.hash()?;
        let groups = reader.integer()?;
        let transactions = reader.integer()?;
        ensure!((1..=MAX_BLOCK_GROUPS).contains(&groups), "invalid group count");
        ensure!(transactions > 0 && transactions <= reader.0.len() as u64 / 72,
                "transaction count exceeds payload");
        let occupancies = (0..groups).map(|_| reader.integer().and_then(|n| Ok(usize::try_from(n)?)))
            .collect::<Result<Vec<_>>>()?;
        let mut tuples = Vec::new();
        for _ in 0..transactions {
            tuples.push(Tx { pk: reader.hash()?, msg: reader.hash()?, index: reader.integer()? });
        }
        blocks.push(PublicBlock { height, predecessor, occupancies, transactions: tuples });
    }
    ensure!(reader.0.is_empty(), "trailing history bytes");
    let endpoint = reconstruct(&blocks, genesis, budget, mode)?;
    Ok((blocks, endpoint))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcc::make_block;

    fn fixture() -> PublicBlock {
        let built = make_block(7, 6, 4);
        PublicBlock { height: 1, predecessor: zero_hash(), occupancies: vec![4, 2],
                      transactions: built.groups.into_iter().flatten().collect() }
    }

    #[test]
    fn partition_changes_the_named_commitment() -> Result<()> {
        let block = fixture();
        let expected = block.commitment(4, GroupMode::Wots)?;
        assert_eq!(expected, make_block(7, 6, 4).tx_root);
        let mut other = block.clone();
        other.occupancies = vec![3, 3];
        assert_ne!(expected, other.commitment(4, GroupMode::Wots)?);
        other.occupancies = vec![4];
        assert!(other.commitment(4, GroupMode::Wots).is_err());
        other.transactions.truncate(4);
        assert_ne!(expected, other.commitment(4, GroupMode::Wots)?);
        for partition in [vec![0, 4, 2], vec![5, 1], vec![4, 1], vec![]] {
            other = block.clone();
            other.occupancies = partition;
            assert!(other.commitment(4, GroupMode::Wots).is_err());
        }
        Ok(())
    }

    #[test]
    fn public_encoding_roundtrip_and_size() -> Result<()> {
        let block = fixture();
        let encoded = encode(&[block.clone()], zero_hash(), 4, GroupMode::Wots)?;
        assert_eq!(encoded.len(), 8 + 56 + 8 * 2 + 72 * 6);
        let decoded = decode(&encoded, zero_hash(), 4, GroupMode::Wots)?;
        assert_eq!(decoded[0].transactions, block.transactions);
        assert_eq!(decoded[0].occupancies, block.occupancies);
        for n in 0..encoded.len() {
            assert!(decode(&encoded[..n], zero_hash(), 4, GroupMode::Wots).is_err());
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(decode(&trailing, zero_hash(), 4, GroupMode::Wots).is_err());
        let mut noncanonical = encoded;
        noncanonical[80..88].copy_from_slice(&F::ORDER.to_le_bytes());
        assert!(decode(&noncanonical, zero_hash(), 4, GroupMode::Wots).is_err());
        Ok(())
    }

    #[test]
    #[ignore = "builds all three recursive layers and verifies a named public history"]
    fn named_history_checks_real_chain_proof() -> Result<()> {
        use crate::pcc::{build_group_circuit, build_block_circuit, build_chain_circuit, prove_group};
        let gc = build_group_circuit(4);
        let bc = build_block_circuit(&gc);
        let cc = build_chain_circuit(&bc, &gc);
        let built = make_block(7, 6, 4);
        let block = fixture();
        let bid = block_id(1, zero_hash(), built.tx_root);
        let mut aggregate = None;
        for (j, (txs, sigs)) in built.groups.iter().zip(&built.sigs).enumerate() {
            let group = prove_group(&gc, bid, j as u64, txs, sigs)?;
            aggregate = Some(bc.step(bid, &group, aggregate.as_ref())?);
        }
        let proof = cc.step(zero_hash(), 1, zero_hash(), aggregate.as_ref().unwrap(), None)?;
        verify_named_history(&cc, &proof, &[block.clone()], zero_hash(), 4, GroupMode::Wots)?;
        let mut changed = block.clone();
        changed.occupancies = vec![3, 3];
        assert!(verify_named_history(&cc, &proof, &[changed], zero_hash(), 4, GroupMode::Wots).is_err());
        let mut shortened = block;
        shortened.occupancies = vec![4];
        shortened.transactions.truncate(4);
        assert!(verify_named_history(&cc, &proof, &[shortened], zero_hash(), 4, GroupMode::Wots).is_err());
        Ok(())
    }

    #[test]
    fn history_rejects_gaps_and_wrong_predecessors() -> Result<()> {
        let block = fixture();
        let (_, _, tip) = reconstruct(&[block.clone()], zero_hash(), 4, GroupMode::Wots)?;
        let mut second = block.clone();
        second.height = 2;
        second.predecessor = tip;
        reconstruct(&[block.clone(), second.clone()], zero_hash(), 4, GroupMode::Wots)?;
        second.height = 3;
        assert!(reconstruct(&[block.clone(), second.clone()], zero_hash(), 4, GroupMode::Wots).is_err());
        second.height = 2;
        second.predecessor = zero_hash();
        assert!(reconstruct(&[block, second], zero_hash(), 4, GroupMode::Wots).is_err());
        Ok(())
    }
}
