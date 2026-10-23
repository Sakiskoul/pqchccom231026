use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Instant;

use pcb_recursive::mem::peak_working_set_mb;
use pcb_recursive::pcc::{
    block_id, build_block_circuit, build_chain_circuit, build_group_circuit_mode,
    detect_index_reuse, digits_of, make_xmss_block, make_xmss_block_from_tree, prove_group_full,
    tip_hash, GroupMode, Tx, F, L,
};
use pcb_recursive::wots_poseidon;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::hash_types::HashOut;

fn attempt<T>(f: impl FnOnce() -> anyhow::Result<T>) -> Result<T, &'static str> {
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let outcome = catch_unwind(AssertUnwindSafe(f));
    std::panic::set_hook(hook);
    match outcome {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(_)) => Err("producer-error"),
        Err(payload) => {
            let message = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("");
            if message.contains("Partition containing")
                && message.contains("was set twice with different values")
            {
                Err("witness-conflict")
            } else {
                Err("unexpected-panic")
            }
        }
    }
}

fn label<T>(outcome: Result<T, &'static str>, verifies: impl FnOnce(T) -> bool) -> &'static str {
    match outcome {
        Err(cause) => cause,
        Ok(proof) => {
            if verifies(proof) {
                "ACCEPTED"
            } else {
                "reject(verify)"
            }
        }
    }
}

fn root_id(root: HashOut<F>) -> String {
    root.elements
        .iter()
        .map(|value| format!("{:016x}", value.to_canonical_u64()))
        .collect()
}

fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().collect();
    let heights: Vec<usize> = a
        .get(1)
        .cloned()
        .unwrap_or_else(|| "5,10".into())
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    let blocks: usize = a.get(2).and_then(|s| s.parse().ok()).unwrap_or(4);
    let k: usize = a.get(3).and_then(|s| s.parse().ok()).unwrap_or(4);
    let g: usize = a.get(4).and_then(|s| s.parse().ok()).unwrap_or(2);
    let reps: usize = a.get(5).and_then(|s| s.parse().ok()).unwrap_or(5);
    anyhow::ensure!(!heights.is_empty(), "at least one XMSS height is required");
    anyhow::ensure!(blocks > 0, "the chain must contain at least one block");
    anyhow::ensure!(k > 0, "each block must contain at least one transaction");
    anyhow::ensure!(g > 0, "the group budget must be positive");
    anyhow::ensure!(
        reps >= 5,
        "XMSS measurements require at least five repetitions"
    );
    for &height in &heights {
        anyhow::ensure!(
            height < usize::BITS as usize,
            "XMSS tree height exceeds the host index width"
        );
        let consumed = blocks
            .checked_mul(k)
            .ok_or_else(|| anyhow::anyhow!("XMSS trajectory length overflows usize"))?;
        anyhow::ensure!(
            consumed <= (1usize << height),
            "XMSS trajectory consumes {consumed} leaves from a height-{height} tree"
        );
    }

    println!("mode,height,blocks,txs_total,group_prove_ms,group_proof_bytes,block_proof_bytes,chain_proof_bytes,chain_step_ms,chain_verify_ms,peak_mb,group_build_ms,rep,xmss_root,index_first,index_last");

    for &h in &heights {
        let mode = GroupMode::Xmss { height: h };
        let t = Instant::now();
        let gc = build_group_circuit_mode(g, mode);
        let build_ms = t.elapsed().as_secs_f64() * 1000.0;
        let bc = build_block_circuit(&gc);
        let cc = build_chain_circuit(&bc, &gc);
        eprintln!(
            "h={h}: group 2^{}, block 2^{}, chain 2^{} ({:.1}s to build the group circuit)",
            gc.data.common.degree_bits(),
            bc.data.common.degree_bits(),
            cc.data.common.degree_bits(),
            build_ms / 1000.0
        );

        let genesis = HashOut {
            elements: [F::from_canonical_u64(0xACE0); 4],
        };

        let warm_seed = 0xC01D_0000 + h as u64;
        let warm_tree = wots_poseidon::xmss_keygen(warm_seed, h, L);
        let warm = make_xmss_block_from_tree(&warm_tree, 0, k, g, warm_seed);
        let warm_bid = block_id(1, genesis, warm.tx_root);
        let mut warm_block = None;
        for (j, ((txs, sigs), paths)) in warm
            .groups
            .iter()
            .zip(warm.sigs.iter())
            .zip(warm.paths.iter())
            .enumerate()
        {
            let proof = prove_group_full(&gc, warm_bid, j as u64, txs, sigs, paths)?;
            warm_block = Some(bc.step(warm_bid, &proof, warm_block.as_ref())?);
        }
        let warm_block = warm_block.expect("warm-up block has at least one group");
        let _ = cc.step(genesis, 1, genesis, &warm_block, None)?;

        let mut last_blocks: Vec<Vec<Tx>> = Vec::new();
        for rep in 1..=reps {
            let mut prev_hash = genesis;
            let mut chain_proof = None;
            let mut all_blocks: Vec<Vec<Tx>> = Vec::new();
            let mut total = 0u64;
            let tree_seed = 0x5EED + (rep as u64 - 1) * 0x1_0000 + h as u64;
            let tree = wots_poseidon::xmss_keygen(tree_seed, h, L);
            let tree_id = root_id(tree.root);

            for height in 1..=blocks {
                let first_index = (height - 1) * k;
                let last_index = first_index + k - 1;
                let message_seed = tree_seed.wrapping_add((height as u64) << 32);
                let bb = make_xmss_block_from_tree(&tree, first_index, k, g, message_seed);
                total += bb.num_txs;
                all_blocks.push(bb.groups.iter().flatten().cloned().collect());
                let bid = block_id(height as u64, prev_hash, bb.tx_root);

                let t0 = Instant::now();
                let mut gps = Vec::new();
                for (j, ((txs, sigs), paths)) in bb
                    .groups
                    .iter()
                    .zip(bb.sigs.iter())
                    .zip(bb.paths.iter())
                    .enumerate()
                {
                    let p = prove_group_full(&gc, bid, j as u64, txs, sigs, paths)?;
                    gc.data.verify(p.clone())?;
                    gps.push(p);
                }
                let gms = t0.elapsed().as_secs_f64() * 1000.0;

                let mut bp = None;
                for p in &gps {
                    bp = Some(bc.step(bid, p, bp.as_ref())?);
                }
                let bp = bp.expect("measured block has at least one group");
                bc.verify_block(&bp, bid, bb.tx_root, bb.groups.len() as u64, bb.num_txs)?;

                let t1 = Instant::now();
                let next = cc.step(genesis, height as u64, prev_hash, &bp, chain_proof.as_ref())?;
                let cms = t1.elapsed().as_secs_f64() * 1000.0;
                let t2 = Instant::now();
                let (hh, _, _) = cc.verify_chain(&next, genesis)?;
                let vms = t2.elapsed().as_secs_f64() * 1000.0;
                assert_eq!(hh, height as u64);

                prev_hash = tip_hash(bid, bb.tx_root, bb.groups.len() as u64, bb.num_txs);
                println!(
                    "xmss,{h},{height},{total},{gms:.1},{},{},{},{cms:.1},{vms:.3},{:.0},{build_ms:.0},{rep},{tree_id},{first_index},{last_index}",
                    gps[0].to_bytes().len(),
                    bp.to_bytes().len(),
                    next.to_bytes().len(),
                    peak_working_set_mb()
                );
                chain_proof = Some(next);
            }
            anyhow::ensure!(
                detect_index_reuse(&all_blocks).is_empty(),
                "honest XMSS trajectory reused a one-time leaf"
            );
            last_blocks = all_blocks;
        }

        if h == *heights.iter().min().unwrap() {
            eprintln!("\nlayer,attack,binding mechanism,outcome");
            let bb = make_xmss_block(777, k, g, h);
            let bid = block_id(1, genesis, bb.tx_root);
            let mut outcomes: Vec<(String, bool)> = Vec::new();
            let mut report = |attack: &str, bound: &str, api: &str, circuit: &str, passed: bool| {
                let csv = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
                eprintln!("xmss,{attack},{bound},{api},{circuit}");
                let mut fields = vec![
                    "ADV".to_string(),
                    "xmss".to_string(),
                    csv(attack),
                    csv(bound),
                    csv(api),
                    csv(circuit),
                ];
                fields.resize(16, String::new());
                println!("{}", fields.join(","));
                outcomes.push((attack.to_string(), passed));
            };

            let good = prove_group_full(&gc, bid, 0, &bb.groups[0], &bb.sigs[0], &bb.paths[0]);
            let control = if good.is_ok() { "ACCEPTED" } else { "producer-error" };
            report(
                "honest XMSS group (control)",
                "none needed",
                control,
                control,
                good.is_ok(),
            );

            let mut txs = bb.groups[0].clone();
            txs[0].pk = HashOut {
                elements: [F::from_canonical_u64(1); 4],
            };
            let o = attempt(|| prove_group_full(&gc, bid, 0, &txs, &bb.sigs[0], &bb.paths[0]));
            let o = label(o, |proof| gc.data.verify(proof).is_ok());
            report(
                "wrong XMSS root",
                "path recomputation connected to the public root",
                o,
                o,
                o != "ACCEPTED" && o != "unexpected-panic",
            );

            let mut paths = bb.paths[0].clone();
            paths[0][0] = HashOut {
                elements: [F::from_canonical_u64(2); 4],
            };
            let o = attempt(|| prove_group_full(&gc, bid, 0, &bb.groups[0], &bb.sigs[0], &paths));
            let o = label(o, |proof| gc.data.verify(proof).is_ok());
            report(
                "wrong authentication path",
                "in-circuit Merkle path",
                o,
                o,
                o != "ACCEPTED" && o != "unexpected-panic",
            );

            let mut txs = bb.groups[0].clone();
            txs[0].index ^= 1;
            let o = attempt(|| prove_group_full(&gc, bid, 0, &txs, &bb.sigs[0], &bb.paths[0]));
            let o = label(o, |proof| gc.data.verify(proof).is_ok());
            report(
                "wrong leaf index",
                "index bits drive the path and enter the leaf",
                o,
                o,
                o != "ACCEPTED" && o != "unexpected-panic",
            );

            let mut txs = bb.groups[0].clone();
            txs[0].msg = HashOut {
                elements: [F::from_canonical_u64(3); 4],
            };
            let o = attempt(|| prove_group_full(&gc, bid, 0, &txs, &bb.sigs[0], &bb.paths[0]));
            let o = label(o, |proof| gc.data.verify(proof).is_ok());
            report(
                "tampered message",
                "in-circuit message-to-digit derivation",
                o,
                o,
                o != "ACCEPTED" && o != "unexpected-panic",
            );

            let mut sigs = bb.sigs[0].clone();
            sigs[0][0] = HashOut {
                elements: [F::from_canonical_u64(4); 4],
            };
            let o = attempt(|| prove_group_full(&gc, bid, 0, &bb.groups[0], &sigs, &bb.paths[0]));
            let o = label(o, |proof| gc.data.verify(proof).is_ok());
            report(
                "forged WOTS signature at a valid leaf",
                "chain fold to the leaf",
                o,
                o,
                o != "ACCEPTED" && o != "unexpected-panic",
            );

            let honest = prove_group_full(&gc, bid, 0, &bb.groups[0], &bb.sigs[0], &bb.paths[0])?;
            let other_prev = tip_hash(bid, bb.tx_root, bb.groups.len() as u64, bb.num_txs);
            let other_bid = block_id(2, other_prev, bb.tx_root);
            let api = label(attempt(|| bc.step(other_bid, &honest, None)), |proof| {
                bc.data.verify(proof).is_ok()
            });
            let circuit = label(attempt(|| bc.step_unchecked(other_bid, &honest, None)), |proof| {
                bc.data.verify(proof).is_ok()
            });
            report(
                "group proof replayed into another block",
                "group block-id public input",
                api,
                circuit,
                api != "ACCEPTED"
                    && circuit != "ACCEPTED"
                    && api != "unexpected-panic"
                    && circuit != "unexpected-panic",
            );

            let reused = {
                let x = wots_poseidon::xmss_keygen(999, h, L);
                let m1 = HashOut {
                    elements: [F::from_canonical_u64(10); 4],
                };
                let m2 = HashOut {
                    elements: [F::from_canonical_u64(11); 4],
                };
                let t1 = Tx {
                    pk: x.root,
                    msg: m1,
                    index: 3,
                };
                let t2 = Tx {
                    pk: x.root,
                    msg: m2,
                    index: 3,
                };
                let _ = digits_of(m1);
                vec![vec![t1], vec![t2]]
            };
            let dup = detect_index_reuse(&reused);
            let detected = if dup.is_empty() { "missed" } else { "detected" };
            report(
                "one-time leaf-index reuse across blocks",
                "public root and index pair",
                detected,
                "not-applicable",
                !dup.is_empty(),
            );

            let dup2 = detect_index_reuse(&last_blocks);
            let clear = if dup2.is_empty() { "clear" } else { "false-positive" };
            report(
                "honest chain scanned for reuse (control)",
                "public root and index pair",
                clear,
                "not-applicable",
                dup2.is_empty(),
            );

            for (name, passed) in &outcomes {
                anyhow::ensure!(*passed, "XMSS gate failed on '{name}'");
            }
        }
    }
    Ok(())
}
