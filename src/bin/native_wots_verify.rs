use std::hint::black_box;
use std::time::Instant;

use pcb_recursive::pcc::{make_block, native_verify};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let maximum: usize = args
        .get(1)
        .and_then(|value| value.parse().ok())
        .unwrap_or(512);
    let repetitions: usize = args
        .get(2)
        .and_then(|value| value.parse().ok())
        .unwrap_or(20);
    assert!(maximum > 0, "maximum transaction count must be positive");
    assert!(repetitions > 0, "repetition count must be positive");

    let block = make_block(0x4152_4348_4956_45, maximum, 4);
    let transactions = block.groups.iter().flatten().collect::<Vec<_>>();
    let signatures = block.sigs.iter().flatten().collect::<Vec<_>>();
    let requested = match args.get(3) {
        Some(list) => list
            .split(',')
            .map(|value| value.trim().parse::<usize>().expect("history sizes must be integers"))
            .collect::<Vec<_>>(),
        None => vec![1usize, 16, 32, 64, 69, 128, 256, 512],
    }
    .into_iter()
    .filter(|count| *count <= maximum)
    .collect::<Vec<_>>();
    assert!(!requested.is_empty(), "no history size fits the maximum");

    println!("transactions,rep,native_verify_ms,valid");
    for count in requested {
        let warmup_valid = transactions[..count]
            .iter()
            .zip(&signatures[..count])
            .all(|(transaction, signature)| native_verify(transaction, signature));
        assert!(warmup_valid, "warm-up verification failed");

        for repetition in 1..=repetitions {
            let started = Instant::now();
            let valid = transactions[..count]
                .iter()
                .zip(&signatures[..count])
                .all(|(transaction, signature)| native_verify(transaction, signature));
            let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
            assert!(black_box(valid), "native verification failed");
            println!("{count},{repetition},{elapsed_ms:.6},true");
        }
    }
}
