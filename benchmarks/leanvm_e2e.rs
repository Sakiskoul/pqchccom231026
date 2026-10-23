use std::io::Write;
use std::time::Instant;

use lean_multisig::{
    aggregate_single_message_signatures, merge_single_message_aggregates, setup_prover,
    verify_multi_message_aggregate, verify_single_message_aggregate, xmss_key_gen_from_seed,
    xmss_sign, xmss_verify, MultiMessageAggregateSignature, MAX_RECURSIONS,
};

fn elapsed_ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let n: usize = args.get(1).expect("signature count").parse().unwrap();
    let seed: u64 = args.get(2).expect("input seed").parse().unwrap();
    let reps: usize = args.get(3).map_or(1, |s| s.parse().unwrap());
    let output_prefix = args.get(4);
    let warmups: usize = args.get(5).map_or(1, |s| s.parse().unwrap());
    let message_fixture = args.get(6).map(|path| std::fs::read(path).unwrap());
    if let Some(bytes) = &message_fixture { assert_eq!(bytes.len(), 32 * n); }
    assert!(warmups <= 1);
    assert!((1..=MAX_RECURSIONS).contains(&n));
    assert!(reps > 0);
    let setup_start = Instant::now();
    setup_prover();
    let setup_ms = elapsed_ms(setup_start);
    let input_start = Instant::now();
    let inputs: Vec<_> = (0..n).map(|i| {
        let mut key_seed = [0u8; 32];
        key_seed[..8].copy_from_slice(&seed.to_le_bytes());
        key_seed[8..16].copy_from_slice(&(i as u64).to_le_bytes());
        key_seed[16..24].copy_from_slice(b"PCB-E2E1");
        let mut message = key_seed;
        message[24..].copy_from_slice(b"MESSAGE1");
        if let Some(bytes) = &message_fixture {
            message.copy_from_slice(&bytes[32*i..32*(i+1)]);
        }
        let slot = 111u32;
        let (pk, sk) = xmss_key_gen_from_seed(key_seed, u64::from(slot), 1).unwrap();
        let signature = xmss_sign(&sk, slot, &message).unwrap();
        xmss_verify(&pk, slot, &message, &signature).unwrap();
        (pk, signature, message, slot)
    }).collect();
    let input_ms = elapsed_ms(input_start);

    for iteration in 0..reps + warmups {
        let warmup = iteration < warmups;
        let repetition = if warmup { 0 } else { iteration + 1 - warmups };
        let online_start = Instant::now();
        let leaf_start = Instant::now();
        let leaves: Vec<_> = inputs.iter().map(|(pk, signature, message, slot)| {
            let proof = aggregate_single_message_signatures(
                &[], vec![(pk.clone(), signature.clone())], *message, *slot, 2,
            ).unwrap();
            verify_single_message_aggregate(&proof).unwrap();
            proof
        }).collect();
        let leaf_ms = elapsed_ms(leaf_start);
        let merge_start = Instant::now();
        let proof = merge_single_message_aggregates(leaves, 2).unwrap();
        let merge_ms = elapsed_ms(merge_start);
        let serialization_start = Instant::now();
        let bytes = proof.to_bytes();
        let without_keys = proof.to_bytes_without_pubkeys().len();
        let decoded = MultiMessageAggregateSignature::from_bytes(&bytes).unwrap();
        let serialization_ms = elapsed_ms(serialization_start);
        let verify_start = Instant::now();
        assert_eq!(decoded.info.len(), inputs.len());
        for (info, (pk, _, message, slot)) in decoded.info.iter().zip(&inputs) {
            assert_eq!(info.core.message, *message);
            assert_eq!(info.core.slot, *slot);
            assert_eq!(info.pubkeys.as_slice(), std::slice::from_ref(pk));
        }
        verify_multi_message_aggregate(&decoded).unwrap();
        let verify_ms = elapsed_ms(verify_start);
        let online_ms = elapsed_ms(online_start);
        if iteration == 0 {
            let mut wrong = decoded.clone();
            wrong.info[0].core.message[0] ^= 1;
            assert!(verify_multi_message_aggregate(&wrong).is_err());
        }
        if let Some(prefix) = output_prefix.filter(|_| !warmup) {
            let mut file = std::fs::OpenOptions::new().write(true).create_new(true)
                .open(format!("{prefix}-r{repetition}.proof")).unwrap();
            file.write_all(&bytes).unwrap();
            file.sync_all().unwrap();
        }
        println!("{}", serde_json::json!({
            "implementation": "leanvm-multimessage-e2e",
            "upstream_commit": "98cb2ad4bdc52618674c0f8f91f715a75349ff6f",
            "n": n, "seed": seed, "rep": repetition, "warmup": warmup,
            "log_inv_rate": 2, "prox_gaps_conjecture": false,
            "distinct_messages": true, "distinct_keys": true, "expected_instance_checked": true,
            "message_source": if message_fixture.is_some() { "pcb_fixture" } else { "synthetic_leanvm_pilot" },
            "setup_ms": setup_ms, "input_ms": input_ms, "leaf_ms": leaf_ms,
            "merge_ms": merge_ms, "serialization_ms": serialization_ms, "verify_ms": verify_ms,
            "online_ms": online_ms, "proof_bytes_with_keys": bytes.len(),
            "proof_bytes_without_keys": without_keys,
            "peak_rss_bytes": system_info::peak_rss_bytes(), "verified": true,
            "chain_statement": false,
        }));
    }
}
