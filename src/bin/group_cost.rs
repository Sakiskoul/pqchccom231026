use std::time::Instant;

use pcb_recursive::mem::peak_working_set_mb;
use pcb_recursive::pcc::{
    block_id, build_block_circuit, build_group_circuit, make_block, prove_group, zero_hash,
};
use plonky2::field::types::PrimeField64;

#[cfg(windows)]
fn pin_to_mask(mask: u32) -> anyhow::Result<()> {
    use winapi::um::processthreadsapi::GetCurrentProcess;
    use winapi::um::winbase::SetProcessAffinityMask;
    let ok = unsafe { SetProcessAffinityMask(GetCurrentProcess(), mask) };
    anyhow::ensure!(ok != 0, "failed to set process affinity mask {mask:#x}");
    Ok(())
}

#[cfg(not(windows))]
fn pin_to_mask(_mask: u32) -> anyhow::Result<()> {
    Ok(())
}

fn median(v: &mut [f64]) -> f64 {
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

fn iqr(v: &[f64]) -> f64 {
    if v.len() < 4 {
        return 0.0;
    }
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    s[3 * s.len() / 4] - s[s.len() / 4]
}

fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().collect();
    let g: usize = a.get(1).and_then(|s| s.parse().ok()).unwrap_or(4);
    anyhow::ensure!(g > 0, "circuit budget must be positive");
    let spec = a.get(2).cloned().unwrap_or_else(|| {
        (1..=g).map(|n| n.to_string()).collect::<Vec<_>>().join(",")
    });
    let reps: usize = a.get(3).and_then(|s| s.parse().ok()).unwrap_or(5);
    anyhow::ensure!(reps > 0, "at least one repetition is required");
    if let Some(raw) = a.get(4) {
        let raw = raw.trim_start_matches("0x");
        let mask = u32::from_str_radix(raw, 16)?;
        anyhow::ensure!(mask != 0, "affinity mask must not be zero");
        pin_to_mask(mask)?;
    }
    let occupancies: Vec<usize> = spec.split(',').filter_map(|s| s.trim().parse().ok()).collect();
    anyhow::ensure!(!occupancies.is_empty(), "no occupancies supplied");
    anyhow::ensure!(
        occupancies.iter().all(|&n| n > 0 && n <= g),
        "every occupancy must be in 1..=circuit_budget"
    );

    let t0 = Instant::now();
    let gc = build_group_circuit(g);
    let build_ms = t0.elapsed().as_secs_f64() * 1000.0;
    let circuit_id = gc
        .circuit_id
        .elements
        .iter()
        .map(|e| format!("{:016x}", e.to_canonical_u64()))
        .collect::<String>();

    struct Row {
        occupancy: usize,
        prove_ms: f64,
        peak_mb: f64,
        proof_bytes: usize,
        verify_ms: f64,
        prove_iqr_ms: f64,
        verify_iqr_ms: f64,
    }
    let mut rows = Vec::new();
    for &n in &occupancies {
        let bb = make_block(0xC057 + n as u64, n, g);
        let bid = block_id(1, zero_hash(), bb.tx_root);

        let warm = prove_group(&gc, bid, 0, &bb.groups[0], &bb.sigs[0])?;
        gc.data.verify(warm)?;

        let mut pv = Vec::with_capacity(reps);
        let mut vv = Vec::with_capacity(reps);
        let mut proof = None;
        let mut peak = 0.0f64;
        for _ in 0..reps {
            let t = Instant::now();
            let p = prove_group(&gc, bid, 0, &bb.groups[0], &bb.sigs[0])?;
            pv.push(t.elapsed().as_secs_f64() * 1000.0);
            peak = peak.max(peak_working_set_mb());
            let t = Instant::now();
            gc.data.verify(p.clone())?;
            vv.push(t.elapsed().as_secs_f64() * 1000.0);
            proof = Some(p);
        }
        let proof = proof.unwrap();

        rows.push(Row {
            occupancy: n,
            prove_ms: median(&mut pv.clone()),
            peak_mb: peak,
            proof_bytes: proof.to_bytes().len(),
            verify_ms: median(&mut vv.clone()),
            prove_iqr_ms: iqr(&pv),
            verify_iqr_ms: iqr(&vv),
        });
    }

    let bc = build_block_circuit(&gc);
    let bb2 = make_block(0xC057 + g as u64 + 7919, g, g);
    let bid2 = block_id(1, zero_hash(), bb2.tx_root);
    let p0 = prove_group(&gc, bid2, 0, &bb2.groups[0], &bb2.sigs[0])?;
    let p1 = prove_group(&gc, bid2, 1, &bb2.groups[0], &bb2.sigs[0])?;
    let s1 = bc.step(bid2, &p0, None)?;
    let t = Instant::now();
    let _s2 = bc.step(bid2, &p1, Some(&s1))?;
    let agg_ms = t.elapsed().as_secs_f64() * 1000.0;
    let agg_peak = peak_working_set_mb();

    println!("circuit_budget,occupancy,circuit_id,prove_ms,peak_mb,proof_bytes,verify_ms,agg_step_ms,agg_peak_mb,build_ms,prove_iqr_ms,verify_iqr_ms,reps");
    for r in rows {
        println!(
            "{g},{},{circuit_id},{:.1},{:.0},{},{:.3},{:.1},{:.0},{:.0},{:.1},{:.3},{reps}",
            r.occupancy,
            r.prove_ms,
            r.peak_mb,
            r.proof_bytes,
            r.verify_ms,
            agg_ms,
            agg_peak,
            build_ms,
            r.prove_iqr_ms,
            r.verify_iqr_ms
        );
    }
    Ok(())
}
