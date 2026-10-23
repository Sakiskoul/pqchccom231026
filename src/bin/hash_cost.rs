use std::time::Instant;

use pcb_recursive::mem::peak_working_set_mb;
use pcb_recursive::sha256::{
    compress_target, constant_u32, sha256_native, virtual_u32, U32Target, H0,
};
use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::PoseidonGoldilocksConfig;

type C = PoseidonGoldilocksConfig;
type F = pcb_recursive::sha256::F;
const D: usize = 2;

fn median(v: &mut Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len();
    if n == 0 {
        0.0
    } else if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
}

struct Measured {
    gates: usize,
    degree_bits: usize,
    build_ms: f64,
    prove_ms: f64,
    verify_ms: f64,
    bytes: usize,
    peak_mb: f64,
}

fn measure_sha256(n: usize, reps: usize) -> Measured {
    let t = Instant::now();
    let mut b = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let mut state: [U32Target; 8] = core::array::from_fn(|i| constant_u32(&mut b, H0[i]));
    let block: [U32Target; 16] = core::array::from_fn(|_| virtual_u32(&mut b));
    for _ in 0..n {
        state = compress_target(&mut b, &state, &block);
    }
    for s in &state {
        b.register_public_input(s.value);
    }
    let gates = b.num_gates();
    let data = b.build::<C>();
    let build_ms = t.elapsed().as_secs_f64() * 1000.0;

    let witness = || {
        let mut pw = PartialWitness::<F>::new();
        for (i, target) in block.iter().enumerate() {
            pw.set_target(target.value, F::from_canonical_u64(0x0101_0100 + i as u64));
        }
        pw
    };
    let warm = data.prove(witness()).expect("sha256 warm-up prove");
    data.verify(warm).expect("sha256 warm-up verify");

    let mut pv = Vec::new();
    let mut vv = Vec::new();
    let mut bytes = 0;
    let mut peak = 0.0;
    for _ in 0..reps {
        let t = Instant::now();
        let p = data.prove(witness()).expect("sha256 prove");
        pv.push(t.elapsed().as_secs_f64() * 1000.0);
        bytes = p.to_bytes().len();
        peak = peak_working_set_mb();
        let t = Instant::now();
        data.verify(p).expect("sha256 verify");
        vv.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    Measured {
        gates,
        degree_bits: data.common.degree_bits(),
        build_ms,
        prove_ms: median(&mut pv),
        verify_ms: median(&mut vv),
        bytes,
        peak_mb: peak,
    }
}

fn measure_poseidon(n: usize, reps: usize) -> Measured {
    let t = Instant::now();
    let mut b = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let inp: HashOutTarget = b.add_virtual_hash();
    let mut cur = inp;
    for _ in 0..n {
        cur = b.hash_n_to_hash_no_pad::<PoseidonHash>(cur.elements.to_vec());
    }
    b.register_public_inputs(&cur.elements);
    let gates = b.num_gates();
    let data = b.build::<C>();
    let build_ms = t.elapsed().as_secs_f64() * 1000.0;

    let witness = || {
        let mut pw = PartialWitness::<F>::new();
        pw.set_hash_target(
            inp,
            plonky2::hash::hash_types::HashOut {
                elements: [F::from_canonical_u64(7); 4],
            },
        );
        pw
    };
    let warm = data.prove(witness()).expect("poseidon warm-up prove");
    data.verify(warm).expect("poseidon warm-up verify");

    let mut pv = Vec::new();
    let mut vv = Vec::new();
    let mut bytes = 0;
    let mut peak = 0.0;
    for _ in 0..reps {
        let t = Instant::now();
        let p = data.prove(witness()).expect("poseidon prove");
        pv.push(t.elapsed().as_secs_f64() * 1000.0);
        bytes = p.to_bytes().len();
        peak = peak_working_set_mb();
        let t = Instant::now();
        data.verify(p).expect("poseidon verify");
        vv.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    Measured {
        gates,
        degree_bits: data.common.degree_bits(),
        build_ms,
        prove_ms: median(&mut pv),
        verify_ms: median(&mut vv),
        bytes,
        peak_mb: peak,
    }
}

fn main() {
    assert_eq!(
        sha256_native(b"abc")
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect::<String>(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );

    let a: Vec<String> = std::env::args().collect();
    let ns_arg = a.get(1).cloned().unwrap_or_else(|| "1,2,4,8,16".into());
    let ns: Vec<usize> = ns_arg
        .split(',')
        .map(|s| {
            s.trim()
                .parse::<usize>()
                .unwrap_or_else(|_| panic!("invalid compression count: {s}"))
        })
        .collect();
    assert!(
        !ns.is_empty() && ns.iter().all(|&n| n > 0),
        "compression counts must be positive"
    );
    let reps: usize = a
        .get(2)
        .map(|s| {
            s.parse::<usize>()
                .unwrap_or_else(|_| panic!("invalid repetition count: {s}"))
        })
        .unwrap_or(5);
    assert!(reps > 0, "repetition count must be positive");
    let selection = a.get(3).map(String::as_str).unwrap_or("both");
    assert!(
        matches!(selection, "sha256" | "poseidon" | "both"),
        "hash selection must be sha256, poseidon, or both"
    );

    println!("n,hash,gates,degree_bits,build_ms,prove_ms,verify_ms,proof_bytes,peak_mb,reps");
    for &n in &ns {
        if matches!(selection, "sha256" | "both") {
            let s = measure_sha256(n, reps);
            println!(
                "{n},sha256,{},{},{:.1},{:.1},{:.3},{},{:.0},{reps}",
                s.gates, s.degree_bits, s.build_ms, s.prove_ms, s.verify_ms, s.bytes, s.peak_mb
            );
        }
        if matches!(selection, "poseidon" | "both") {
            let p = measure_poseidon(n, reps);
            println!(
                "{n},poseidon,{},{},{:.1},{:.1},{:.3},{},{:.0},{reps}",
                p.gates, p.degree_bits, p.build_ms, p.prove_ms, p.verify_ms, p.bytes, p.peak_mb
            );
        }
    }
}
