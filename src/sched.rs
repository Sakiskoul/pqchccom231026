use std::fmt;

use crate::net::WOTS_WITNESS_WIRE_BYTES_PER_TX;

#[derive(Clone, Debug)]
pub struct WorkerProfile {
    pub occupancies: Vec<usize>,
    pub prove_ms: Vec<f64>,
    pub peak_mb: Vec<f64>,
    pub proof_bytes: Vec<f64>,
    pub verify_ms: Vec<f64>,
    pub source: String,
}

impl WorkerProfile {
    fn prove_ms_at(&self, occupancy: usize) -> f64 {
        interp(&self.occupancies, &self.prove_ms, occupancy)
    }

    fn peak_mb_at(&self, _occupancy: usize) -> f64 {
        self.peak_mb.iter().copied().fold(0.0f64, f64::max)
    }

    fn proof_bytes_at(&self, occupancy: usize) -> f64 {
        interp(&self.occupancies, &self.proof_bytes, occupancy)
    }

    fn verify_ms_at(&self, occupancy: usize) -> f64 {
        interp(&self.occupancies, &self.verify_ms, occupancy)
    }

    pub fn observe(&mut self, occupancy: usize, measured_ms: f64, threshold: f64) -> bool {
        if !measured_ms.is_finite()
            || measured_ms <= 0.0
            || !threshold.is_finite()
            || threshold < 0.0
        {
            return false;
        }
        let Some((i, _)) = self
            .occupancies
            .iter()
            .enumerate()
            .min_by_key(|(_, n)| n.abs_diff(occupancy))
        else {
            return false;
        };
        let predicted = self.prove_ms[i].max(1e-9);
        let relative_error = (measured_ms - predicted).abs() / measured_ms.max(1e-9);
        if relative_error <= threshold {
            return false;
        }
        self.prove_ms[i] = 0.75 * predicted + 0.25 * measured_ms;
        true
    }
}

#[derive(Clone, Debug)]
pub struct Worker {
    pub id: usize,
    pub mem_mb: f64,
    pub profile: Option<WorkerProfile>,
    pub cores: usize,
    pub bandwidth_mbps: f64,
    pub latency_ms: f64,
    pub cost_weight: f64,
    pub failure_prob: f64,
    pub load_ms: f64,
}

impl Worker {
    pub fn homogeneous(id: usize, mem_mb: f64) -> Self {
        Worker {
            id,
            mem_mb,
            profile: None,
            cores: 1,
            bandwidth_mbps: 1000.0,
            latency_ms: 0.1,
            cost_weight: 1.0,
            failure_prob: 0.0,
            load_ms: 0.0,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CostModel {
    pub circuit_budget: usize,
    pub circuit_id: String,
    pub sizes: Vec<usize>,
    pub prove_ms: Vec<f64>,
    pub peak_mb: Vec<f64>,
    pub proof_bytes: Vec<f64>,
    pub verify_ms: Vec<f64>,
    pub agg_step_ms: f64,
    pub agg_peak_mb: f64,
    pub witness_bytes_per_tx: f64,
}

fn interp(xs: &[usize], ys: &[f64], g: usize) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    let gf = g as f64;
    if g <= xs[0] {
        return ys[0] * gf / xs[0] as f64;
    }
    for i in 1..xs.len() {
        if g <= xs[i] {
            let (x0, x1) = (xs[i - 1] as f64, xs[i] as f64);
            let t = (gf - x0) / (x1 - x0);
            return ys[i - 1] + t * (ys[i] - ys[i - 1]);
        }
    }
    let n = xs.len();
    let (x0, x1) = (xs[n - 2] as f64, xs[n - 1] as f64);
    let slope = (ys[n - 1] - ys[n - 2]) / (x1 - x0);
    ys[n - 1] + slope * (gf - x1)
}

impl CostModel {
    pub fn from_fixed_circuit_csv(path: &str, expected_budget: usize) -> anyhow::Result<Self> {
        anyhow::ensure!(
            expected_budget > 0,
            "cost-model circuit budget must be positive"
        );
        let txt = std::fs::read_to_string(path)?;
        let mut lines = txt.lines();
        let header: Vec<&str> = lines
            .next()
            .ok_or_else(|| anyhow::anyhow!("empty cost-model CSV"))?
            .split(',')
            .collect();
        let col = |name: &str| -> anyhow::Result<usize> {
            header
                .iter()
                .position(|h| *h == name)
                .ok_or_else(|| anyhow::anyhow!("cost-model CSV lacks column {name}"))
        };
        let i_budget = col("circuit_budget")?;
        let i_occupancy = col("occupancy")?;
        let i_circuit = col("circuit_id")?;
        let i_prove = col("prove_ms")?;
        let i_peak = col("peak_mb")?;
        let i_bytes = col("proof_bytes")?;
        let i_verify = col("verify_ms")?;
        let i_agg = col("agg_step_ms")?;
        let i_agg_peak = col("agg_peak_mb")?;

        let mut rows: Vec<(usize, f64, f64, f64, f64)> = Vec::new();
        let mut circuit_id = String::new();
        let mut agg_step_ms = None;
        let mut agg_peak_mb = None;
        for (line_no, line) in lines.enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let f: Vec<&str> = line.split(',').collect();
            anyhow::ensure!(
                f.len() == header.len(),
                "malformed cost row {}",
                line_no + 2
            );
            let budget: usize = f[i_budget].parse()?;
            anyhow::ensure!(
                budget == expected_budget,
                "cost surface mixes circuit budgets"
            );
            let cid = f[i_circuit].trim();
            anyhow::ensure!(
                cid.len() == 64 && cid.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "circuit identifier must contain 64 hexadecimal digits"
            );
            if circuit_id.is_empty() {
                circuit_id = cid.to_string();
            } else {
                anyhow::ensure!(circuit_id == cid, "cost surface mixes circuit identifiers");
            }
            let occupancy: usize = f[i_occupancy].parse()?;
            anyhow::ensure!(
                occupancy > 0 && occupancy <= expected_budget,
                "occupancy outside the fixed circuit budget"
            );
            let prove_ms: f64 = f[i_prove].parse()?;
            let peak_mb: f64 = f[i_peak].parse()?;
            let proof_bytes: f64 = f[i_bytes].parse()?;
            let verify_ms: f64 = f[i_verify].parse()?;
            let row_agg_step_ms: f64 = f[i_agg].parse()?;
            let row_agg_peak_mb: f64 = f[i_agg_peak].parse()?;
            anyhow::ensure!(
                prove_ms.is_finite() && prove_ms > 0.0,
                "invalid proving time in cost row {}",
                line_no + 2
            );
            anyhow::ensure!(
                peak_mb.is_finite() && peak_mb > 0.0,
                "invalid peak memory in cost row {}",
                line_no + 2
            );
            anyhow::ensure!(
                proof_bytes.is_finite() && proof_bytes > 0.0,
                "invalid proof size in cost row {}",
                line_no + 2
            );
            anyhow::ensure!(
                verify_ms.is_finite() && verify_ms >= 0.0,
                "invalid verification time in cost row {}",
                line_no + 2
            );
            anyhow::ensure!(
                row_agg_step_ms.is_finite() && row_agg_step_ms > 0.0,
                "invalid accumulation time in cost row {}",
                line_no + 2
            );
            anyhow::ensure!(
                row_agg_peak_mb.is_finite() && row_agg_peak_mb > 0.0,
                "invalid accumulator memory in cost row {}",
                line_no + 2
            );
            rows.push((occupancy, prove_ms, peak_mb, proof_bytes, verify_ms));
            if let Some(value) = agg_step_ms {
                anyhow::ensure!(
                    value == row_agg_step_ms,
                    "cost rows disagree on the fixed accumulation time"
                );
            } else {
                agg_step_ms = Some(row_agg_step_ms);
            }
            if let Some(value) = agg_peak_mb {
                anyhow::ensure!(
                    value == row_agg_peak_mb,
                    "cost rows disagree on the fixed accumulator memory"
                );
            } else {
                agg_peak_mb = Some(row_agg_peak_mb);
            }
        }
        rows.sort_by_key(|r| r.0);
        anyhow::ensure!(
            rows.len() == expected_budget,
            "cost surface must measure every occupancy"
        );
        for (i, row) in rows.iter().enumerate() {
            anyhow::ensure!(
                row.0 == i + 1,
                "cost surface has a missing or duplicate occupancy"
            );
        }
        Ok(CostModel {
            circuit_budget: expected_budget,
            circuit_id,
            sizes: rows.iter().map(|r| r.0).collect(),
            prove_ms: rows.iter().map(|r| r.1).collect(),
            peak_mb: rows.iter().map(|r| r.2).collect(),
            proof_bytes: rows.iter().map(|r| r.3).collect(),
            verify_ms: rows.iter().map(|r| r.4).collect(),
            agg_step_ms: agg_step_ms.unwrap_or(0.0),
            agg_peak_mb: agg_peak_mb.unwrap_or(0.0),
            witness_bytes_per_tx: WOTS_WITNESS_WIRE_BYTES_PER_TX as f64,
        })
    }

    pub fn prove_ms_on(&self, g: usize, w: &Worker) -> f64 {
        w.profile
            .as_ref()
            .map(|p| p.prove_ms_at(g))
            .unwrap_or_else(|| interp(&self.sizes, &self.prove_ms, g))
    }
    pub fn peak_mb_of(&self, g: usize) -> f64 {
        let _ = g;
        self.peak_mb.iter().copied().fold(0.0f64, f64::max)
    }
    pub fn proof_bytes_of(&self, g: usize) -> f64 {
        interp(&self.sizes, &self.proof_bytes, g)
    }
    pub fn verify_ms_of(&self, g: usize) -> f64 {
        interp(&self.sizes, &self.verify_ms, g)
    }
    pub fn peak_mb_on(&self, g: usize, w: &Worker) -> f64 {
        w.profile
            .as_ref()
            .map(|p| p.peak_mb_at(g))
            .unwrap_or_else(|| self.peak_mb_of(g))
    }
    pub fn proof_bytes_on(&self, g: usize, w: &Worker) -> f64 {
        w.profile
            .as_ref()
            .map(|p| p.proof_bytes_at(g))
            .unwrap_or_else(|| self.proof_bytes_of(g))
    }
    pub fn verify_ms_on(&self, g: usize, w: &Worker) -> f64 {
        w.profile
            .as_ref()
            .map(|p| p.verify_ms_at(g))
            .unwrap_or_else(|| self.verify_ms_of(g))
    }
    pub fn reference_profile(&self, source: impl Into<String>) -> WorkerProfile {
        WorkerProfile {
            occupancies: self.sizes.clone(),
            prove_ms: self.prove_ms.clone(),
            peak_mb: self.peak_mb.clone(),
            proof_bytes: self.proof_bytes.clone(),
            verify_ms: self.verify_ms.clone(),
            source: source.into(),
        }
    }
    pub fn mean_profile(&self, workers: &[Worker], source: impl Into<String>) -> WorkerProfile {
        let denom = workers.len().max(1) as f64;
        WorkerProfile {
            occupancies: self.sizes.clone(),
            prove_ms: self
                .sizes
                .iter()
                .map(|&g| workers.iter().map(|w| self.prove_ms_on(g, w)).sum::<f64>() / denom)
                .collect(),
            peak_mb: self
                .sizes
                .iter()
                .map(|&g| workers.iter().map(|w| self.peak_mb_on(g, w)).sum::<f64>() / denom)
                .collect(),
            proof_bytes: self
                .sizes
                .iter()
                .map(|&g| workers.iter().map(|w| self.proof_bytes_on(g, w)).sum::<f64>() / denom)
                .collect(),
            verify_ms: self
                .sizes
                .iter()
                .map(|&g| workers.iter().map(|w| self.verify_ms_on(g, w)).sum::<f64>() / denom)
                .collect(),
            source: source.into(),
        }
    }
    pub fn transfer_ms(&self, g: usize, w: &Worker) -> f64 {
        let bytes = self.witness_bytes_per_tx * g as f64 + self.proof_bytes_on(g, w);
        2.0 * w.latency_ms + bytes * 8.0 / (w.bandwidth_mbps * 1000.0)
    }
    pub fn max_feasible(&self, mem_mb: f64, cap: usize) -> Option<usize> {
        if self.peak_mb_of(1) > mem_mb {
            return None;
        }
        self.sizes.iter().copied().filter(|&g| g <= cap && g <= self.circuit_budget).max()
    }
    pub fn max_feasible_on(&self, w: &Worker, cap: usize) -> Option<usize> {
        if self.peak_mb_on(1, w) > w.mem_mb {
            return None;
        }
        self.sizes.iter().copied().filter(|&g| g <= cap && g <= self.circuit_budget).max()
    }
    pub fn aggregate_ms(&self, p: usize) -> f64 {
        p as f64 * self.agg_step_ms
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Objective {
    pub alpha: f64,
    pub beta: f64,
    pub gamma: f64,
    pub delta: f64,
    pub eps: f64,
    pub latency_scale_ms: f64,
    pub storage_scale_bytes: f64,
    pub compute_scale_ms: f64,
    pub comm_scale_ms: f64,
    pub failure_scale_ms: f64,
}

impl Default for Objective {
    fn default() -> Self {
        Objective {
            alpha: 1.0,
            beta: 0.25,
            gamma: 0.25,
            delta: 0.25,
            eps: 0.25,
            latency_scale_ms: 1.0,
            storage_scale_bytes: 1.0,
            compute_scale_ms: 1.0,
            comm_scale_ms: 1.0,
            failure_scale_ms: 1.0,
        }
    }
}

impl Objective {
    pub fn normalised_by(mut self, reference: &PlanCost) -> Self {
        self.latency_scale_ms = reference.makespan_ms.max(1e-9);
        self.storage_scale_bytes = reference.stored_bytes.max(1e-9);
        self.compute_scale_ms = reference.compute_ms.max(1e-9);
        self.comm_scale_ms = reference.comm_ms.max(1e-9);
        self.failure_scale_ms = reference.failure_ms.max(1.0);
        self
    }

    fn latency(&self, value: f64) -> f64 {
        self.alpha * value / self.latency_scale_ms
    }
    fn storage(&self, value: f64) -> f64 {
        self.beta * value / self.storage_scale_bytes
    }
    fn compute(&self, value: f64) -> f64 {
        self.gamma * value / self.compute_scale_ms
    }
    fn communication(&self, value: f64) -> f64 {
        self.delta * value / self.comm_scale_ms
    }
    fn failure(&self, value: f64) -> f64 {
        self.eps * value / self.failure_scale_ms
    }

    fn score(&self, latency: f64, storage: f64, compute: f64, comm: f64, failure: f64) -> f64 {
        self.latency(latency)
            + self.storage(storage)
            + self.compute(compute)
            + self.communication(comm)
            + self.failure(failure)
    }
}

#[derive(Clone, Debug, Default)]
pub struct Plan {
    pub groups: Vec<(usize, usize)>,
    pub target_txs: usize,
    pub circuit_budget: usize,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PlanCost {
    pub makespan_ms: f64,
    pub stored_bytes: f64,
    pub compute_ms: f64,
    pub comm_ms: f64,
    pub failure_ms: f64,
    pub objective: f64,
    pub max_peak_mb: f64,
    pub memory_violations: usize,
    pub num_groups: usize,
    pub imbalance: f64,
    pub feasible: bool,
    pub coverage_txs: usize,
}

impl fmt::Display for PlanCost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "J={:.1} makespan={:.1}ms bytes={:.0} compute={:.1}ms comm={:.1}ms fail={:.1}ms p={} viol={} feasible={}",
            self.objective,
            self.makespan_ms,
            self.stored_bytes,
            self.compute_ms,
            self.comm_ms,
            self.failure_ms,
            self.num_groups,
            self.memory_violations,
            self.feasible
        )
    }
}

pub fn validate_plan(plan: &Plan, workers: &[Worker], cm: &CostModel) -> anyhow::Result<()> {
    anyhow::ensure!(
        plan.groups.len() as u64 <= crate::pcc::MAX_BLOCK_GROUPS,
        "plan exceeds the block circuit's group-count limit"
    );
    anyhow::ensure!(
        plan.circuit_budget == cm.circuit_budget,
        "plan circuit budget does not match the calibrated deployment"
    );
    let covered: usize = plan.groups.iter().map(|(g, _)| *g).sum();
    anyhow::ensure!(covered == plan.target_txs, "plan does not cover the requested transactions");
    if plan.target_txs > 0 {
        anyhow::ensure!(!plan.groups.is_empty(), "non-empty block has no proving groups");
    }
    for &(g, wid) in &plan.groups {
        anyhow::ensure!(g > 0 && g <= cm.circuit_budget, "group occupancy exceeds circuit budget");
        let worker = workers
            .iter()
            .find(|w| w.id == wid)
            .ok_or_else(|| anyhow::anyhow!("plan names unknown worker {wid}"))?;
        anyhow::ensure!(
            cm.peak_mb_on(g, worker) <= worker.mem_mb + 1e-9,
            "worker {wid} cannot hold the fixed group circuit"
        );
    }
    Ok(())
}

pub fn evaluate(plan: &Plan, workers: &[Worker], cm: &CostModel, obj: &Objective) -> PlanCost {
    let mut finish = vec![0.0f64; workers.len()];
    let mut engaged = vec![false; workers.len()];
    for (i, w) in workers.iter().enumerate() {
        finish[i] = w.load_ms;
    }
    let mut stored = 0.0;
    let mut compute = 0.0;
    let mut comm = 0.0;
    let mut fail = 0.0;
    let mut max_peak: f64 = 0.0;
    let mut violations = 0;

    for &(g, wid) in &plan.groups {
        let Some((wi, w)) = workers.iter().enumerate().find(|(_, w)| w.id == wid) else {
            violations += 1;
            continue;
        };
        engaged[wi] = true;
        let t = cm.prove_ms_on(g, w);
        let x = cm.transfer_ms(g, w);
        finish[wi] += t + x;
        stored += cm.proof_bytes_on(g, w);
        compute += t * w.cost_weight;
        comm += x;
        fail += w.failure_prob * (t + x);
        let peak = cm.peak_mb_on(g, w);
        max_peak = max_peak.max(peak);
        if peak > w.mem_mb + 1e-9 {
            violations += 1;
        }
    }
    let worker_finish = finish
        .iter()
        .zip(&engaged)
        .filter_map(|(&f, &used)| used.then_some(f))
        .fold(0.0f64, f64::max);
    let makespan = worker_finish + cm.aggregate_ms(plan.groups.len());
    let busy: Vec<f64> = finish
        .iter()
        .zip(workers)
        .zip(&engaged)
        .filter_map(|((&f, w), &used)| used.then_some(f - w.load_ms))
        .collect();
    let mean = if busy.is_empty() { 0.0 } else { busy.iter().sum::<f64>() / busy.len() as f64 };
    let imbalance = if mean > 0.0 {
        busy.iter().cloned().fold(0.0f64, f64::max) / mean
    } else {
        1.0
    };

    let feasible = validate_plan(plan, workers, cm).is_ok();
    let objective = if feasible {
        obj.score(makespan, stored, compute, comm, fail)
    } else {
        f64::INFINITY
    };

    PlanCost {
        makespan_ms: makespan,
        stored_bytes: stored,
        compute_ms: compute,
        comm_ms: comm,
        failure_ms: fail,
        objective,
        max_peak_mb: max_peak,
        memory_violations: violations,
        num_groups: plan.groups.len(),
        imbalance,
        feasible,
        coverage_txs: plan.groups.iter().map(|(g, _)| *g).sum(),
    }
}

pub fn plan_max_fit(k: usize, workers: &[Worker], cm: &CostModel, cap: usize) -> Plan {
    let eligible: Vec<&Worker> = workers
        .iter()
        .filter(|w| cm.max_feasible_on(w, cap).is_some())
        .collect();
    if eligible.is_empty() {
        return Plan { groups: Vec::new(), target_txs: k, circuit_budget: cm.circuit_budget };
    }
    let g = cm.sizes.iter().copied().filter(|&n| n <= cap).max().unwrap_or(1);
    let mut groups = Vec::new();
    let mut left = k;
    let mut i = 0;
    while left > 0 {
        let s = g.min(left);
        groups.push((s, eligible[i % eligible.len()].id));
        left -= s;
        i += 1;
    }
    Plan { groups, target_txs: k, circuit_budget: cm.circuit_budget }
}

pub fn plan_equal_size(k: usize, workers: &[Worker], cm: &CostModel, cap: usize) -> Plan {
    let eligible: Vec<&Worker> = workers
        .iter()
        .filter(|w| cm.max_feasible_on(w, cap).is_some())
        .collect();
    if eligible.is_empty() {
        return Plan { groups: Vec::new(), target_txs: k, circuit_budget: cm.circuit_budget };
    }
    let m = eligible.len();
    let base = k.div_ceil(m).min(cap).max(1);
    let mut groups = Vec::new();
    let mut left = k;
    let mut i = 0;
    while left > 0 {
        let s = base.min(left);
        groups.push((s, eligible[i % m].id));
        left -= s;
        i += 1;
    }
    Plan { groups, target_txs: k, circuit_budget: cm.circuit_budget }
}

pub fn plan_one_per_group(k: usize, workers: &[Worker], cm: &CostModel) -> Plan {
    let eligible: Vec<&Worker> = workers
        .iter()
        .filter(|w| cm.max_feasible_on(w, 1).is_some())
        .collect();
    if eligible.is_empty() {
        return Plan { groups: Vec::new(), target_txs: k, circuit_budget: cm.circuit_budget };
    }
    let m = eligible.len();
    Plan {
        groups: (0..k).map(|i| (1, eligible[i % m].id)).collect(),
        target_txs: k,
        circuit_budget: cm.circuit_budget,
    }
}

fn fixed_full_groups(k: usize, cap: usize) -> Vec<usize> {
    let mut left = k;
    let mut groups = Vec::new();
    while left > 0 {
        let size = left.min(cap.max(1));
        groups.push(size);
        left -= size;
    }
    groups
}

fn eligible_worker_indices(workers: &[Worker], cm: &CostModel) -> Vec<usize> {
    workers
        .iter()
        .enumerate()
        .filter(|(_, w)| cm.max_feasible_on(w, cm.circuit_budget).is_some())
        .map(|(i, _)| i)
        .collect()
}

pub fn plan_earliest_finish(k: usize, workers: &[Worker], cm: &CostModel, cap: usize) -> Plan {
    let eligible = eligible_worker_indices(workers, cm);
    if eligible.is_empty() {
        return Plan { groups: Vec::new(), target_txs: k, circuit_budget: cm.circuit_budget };
    }
    let mut load: Vec<f64> = workers.iter().map(|w| w.load_ms).collect();
    let mut out = Vec::new();
    for g in fixed_full_groups(k, cap.min(cm.circuit_budget)) {
        let wi = eligible
            .iter()
            .copied()
            .min_by(|&a, &b| {
                let ca = load[a] + cm.prove_ms_on(g, &workers[a]) + cm.transfer_ms(g, &workers[a]);
                let cb = load[b] + cm.prove_ms_on(g, &workers[b]) + cm.transfer_ms(g, &workers[b]);
                ca.partial_cmp(&cb).unwrap()
            })
            .unwrap();
        load[wi] += cm.prove_ms_on(g, &workers[wi]) + cm.transfer_ms(g, &workers[wi]);
        out.push((g, workers[wi].id));
    }
    Plan { groups: out, target_txs: k, circuit_budget: cm.circuit_budget }
}

fn plan_min_or_max_min(
    k: usize,
    workers: &[Worker],
    cm: &CostModel,
    cap: usize,
    choose_max: bool,
) -> Plan {
    let eligible = eligible_worker_indices(workers, cm);
    let mut pending = fixed_full_groups(k, cap.min(cm.circuit_budget));
    if eligible.is_empty() {
        return Plan { groups: Vec::new(), target_txs: k, circuit_budget: cm.circuit_budget };
    }
    let mut load: Vec<f64> = workers.iter().map(|w| w.load_ms).collect();
    let mut out = Vec::new();
    while !pending.is_empty() {
        let candidates: Vec<(usize, usize, f64)> = pending
            .iter()
            .enumerate()
            .map(|(ti, &g)| {
                let (wi, finish) = eligible
                    .iter()
                    .copied()
                    .map(|wi| {
                        let finish = load[wi]
                            + cm.prove_ms_on(g, &workers[wi])
                            + cm.transfer_ms(g, &workers[wi]);
                        (wi, finish)
                    })
                    .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
                    .unwrap();
                (ti, wi, finish)
            })
            .collect();
        let &(ti, wi, _) = if choose_max {
            candidates.iter().max_by(|a, b| a.2.partial_cmp(&b.2).unwrap()).unwrap()
        } else {
            candidates.iter().min_by(|a, b| a.2.partial_cmp(&b.2).unwrap()).unwrap()
        };
        let g = pending.remove(ti);
        load[wi] += cm.prove_ms_on(g, &workers[wi]) + cm.transfer_ms(g, &workers[wi]);
        out.push((g, workers[wi].id));
    }
    Plan { groups: out, target_txs: k, circuit_budget: cm.circuit_budget }
}

pub fn plan_min_min(k: usize, workers: &[Worker], cm: &CostModel, cap: usize) -> Plan {
    plan_min_or_max_min(k, workers, cm, cap, false)
}

pub fn plan_max_min(k: usize, workers: &[Worker], cm: &CostModel, cap: usize) -> Plan {
    plan_min_or_max_min(k, workers, cm, cap, true)
}

pub fn plan_heft(k: usize, workers: &[Worker], cm: &CostModel, cap: usize) -> Plan {
    let eligible = eligible_worker_indices(workers, cm);
    let mut pending = fixed_full_groups(k, cap.min(cm.circuit_budget));
    if eligible.is_empty() {
        return Plan { groups: Vec::new(), target_txs: k, circuit_budget: cm.circuit_budget };
    }
    pending.sort_by(|&a, &b| {
        let rank = |g| {
            eligible
                .iter()
                .map(|&wi| cm.prove_ms_on(g, &workers[wi]) + cm.transfer_ms(g, &workers[wi]))
                .sum::<f64>()
                / eligible.len() as f64
        };
        rank(b).partial_cmp(&rank(a)).unwrap()
    });
    let mut load: Vec<f64> = workers.iter().map(|w| w.load_ms).collect();
    let mut out = Vec::new();
    for g in pending {
        let wi = eligible
            .iter()
            .copied()
            .min_by(|&a, &b| {
                let ca = load[a] + cm.prove_ms_on(g, &workers[a]) + cm.transfer_ms(g, &workers[a]);
                let cb = load[b] + cm.prove_ms_on(g, &workers[b]) + cm.transfer_ms(g, &workers[b]);
                ca.partial_cmp(&cb).unwrap()
            })
            .unwrap();
        load[wi] += cm.prove_ms_on(g, &workers[wi]) + cm.transfer_ms(g, &workers[wi]);
        out.push((g, workers[wi].id));
    }
    Plan { groups: out, target_txs: k, circuit_budget: cm.circuit_budget }
}

pub fn plan_lst_capacity(k: usize, workers: &[Worker], cm: &CostModel, cap: usize) -> Plan {
    if k == 0 {
        return Plan { groups: Vec::new(), target_txs: 0, circuit_budget: cm.circuit_budget };
    }
    let group_budget = cap.min(cm.circuit_budget);
    if group_budget == 0 || workers.is_empty() {
        return Plan { groups: Vec::new(), target_txs: k, circuit_budget: cm.circuit_budget };
    }
    let full_jobs = k / group_budget;
    let remainder = k % group_budget;
    let feasible: Vec<usize> = workers
        .iter()
        .enumerate()
        .filter(|(_, w)| cm.peak_mb_on(group_budget, w) <= w.mem_mb)
        .map(|(i, _)| i)
        .collect();
    if feasible.is_empty() {
        return Plan { groups: Vec::new(), target_txs: k, circuit_budget: cm.circuit_budget };
    }

    let duration = |size: usize, wi: usize| {
        cm.prove_ms_on(size, &workers[wi]) + cm.transfer_ms(size, &workers[wi])
    };
    let assignment_at = |limit: f64| -> Option<Option<usize>> {
        let remainder_workers: Vec<Option<usize>> = if remainder == 0 {
            vec![None]
        } else {
            feasible.iter().copied().map(Some).collect()
        };
        for rem_worker in remainder_workers {
            let mut capacity = 0usize;
            for &wi in &feasible {
                let mut available = limit - workers[wi].load_ms;
                if rem_worker == Some(wi) {
                    available -= duration(remainder, wi);
                }
                if available >= 0.0 {
                    capacity = capacity.saturating_add(
                        (available / duration(group_budget, wi).max(1e-9)).floor() as usize,
                    );
                }
            }
            if capacity >= full_jobs {
                return Some(rem_worker);
            }
        }
        None
    };

    let mut low = workers.iter().map(|w| w.load_ms).fold(0.0f64, f64::max);
    let best_single = feasible
        .iter()
        .map(|&wi| {
            workers[wi].load_ms
                + full_jobs as f64 * duration(group_budget, wi)
                + if remainder > 0 { duration(remainder, wi) } else { 0.0 }
        })
        .fold(f64::INFINITY, f64::min);
    if !best_single.is_finite() {
        return Plan { groups: Vec::new(), target_txs: k, circuit_budget: cm.circuit_budget };
    }
    let mut high = best_single;
    for _ in 0..80 {
        let mid = (low + high) / 2.0;
        if assignment_at(mid).is_some() {
            high = mid;
        } else {
            low = mid;
        }
    }
    let rem_worker = assignment_at(high + 1e-7).flatten();
    let mut remaining = full_jobs;
    let mut groups = Vec::with_capacity(full_jobs + usize::from(remainder > 0));
    for &wi in &feasible {
        let mut available = high - workers[wi].load_ms;
        if rem_worker == Some(wi) {
            available -= duration(remainder, wi);
        }
        let capacity = if available > 0.0 {
            (available / duration(group_budget, wi).max(1e-9)).floor() as usize
        } else {
            0
        };
        for _ in 0..capacity.min(remaining) {
            groups.push((group_budget, workers[wi].id));
        }
        remaining = remaining.saturating_sub(capacity);
    }
    if remaining != 0 {
        return Plan { groups: Vec::new(), target_txs: k, circuit_budget: cm.circuit_budget };
    }
    if let Some(wi) = rem_worker {
        groups.push((remainder, workers[wi].id));
    }
    Plan { groups, target_txs: k, circuit_budget: cm.circuit_budget }
}

pub fn plan_greedy_marginal(
    k: usize,
    workers: &[Worker],
    cm: &CostModel,
    obj: &Objective,
    cap: usize,
) -> Plan {
    greedy_complete(k, workers, workers, cm, obj, cap, &HeuristicConfig::default())
}

#[derive(Clone, Copy, Debug)]
pub struct HeuristicConfig {
    pub memory_aware: bool,
    pub heterogeneity_aware: bool,
    pub network_aware: bool,
    pub aggregation_aware: bool,
    pub failure_aware: bool,
    pub load_balancing: bool,
    pub local_search_rounds: usize,
}

impl Default for HeuristicConfig {
    fn default() -> Self {
        HeuristicConfig {
            memory_aware: true,
            heterogeneity_aware: true,
            network_aware: true,
            aggregation_aware: true,
            failure_aware: true,
            load_balancing: true,
            local_search_rounds: 64,
        }
    }
}

pub fn plan_resource_aware(
    k: usize,
    workers: &[Worker],
    cm: &CostModel,
    obj: &Objective,
    cap: usize,
    cfg: &HeuristicConfig,
) -> Plan {
    if k == 0 {
        return Plan { groups: Vec::new(), target_txs: 0, circuit_budget: cm.circuit_budget };
    }
    if workers.is_empty() {
        return Plan { groups: Vec::new(), target_txs: k, circuit_budget: cm.circuit_budget };
    }
    let mean_profile = cm.mean_profile(workers, "heterogeneity-blind mean");
    let mean_mem = workers.iter().map(|x| x.mem_mb).sum::<f64>() / workers.len() as f64;
    let view: Vec<Worker> = workers
        .iter()
        .map(|w| {
            let mut v = w.clone();
            if !cfg.heterogeneity_aware {
                v.profile = Some(mean_profile.clone());
                v.mem_mb = mean_mem;
            }
            if !cfg.memory_aware {
                v.mem_mb = f64::INFINITY;
            }
            if !cfg.network_aware {
                v.latency_ms = 0.0;
                v.bandwidth_mbps = f64::INFINITY;
            }
            if !cfg.failure_aware {
                v.failure_prob = 0.0;
            }
            v
        })
        .collect();

    let usable: Vec<usize> = (0..view.len())
        .filter(|&i| cm.sizes.iter().any(|&g| g <= cap && cm.peak_mb_on(g, &view[i]) <= view[i].mem_mb))
        .collect();
    if usable.is_empty() {
        return Plan { groups: Vec::new(), target_txs: k, circuit_budget: cm.circuit_budget };
    }

    let mut sizes: Vec<usize> = Vec::with_capacity(view.len());
    for w in &view {
        let feas: Vec<usize> = cm
            .sizes
            .iter()
            .cloned()
            .filter(|&g| g <= cap && cm.peak_mb_on(g, w) <= w.mem_mb)
            .collect();
        let feas = if feas.is_empty() { vec![*cm.sizes.first().unwrap_or(&1)] } else { feas };
        let best = feas
            .iter()
            .cloned()
            .min_by(|&a, &b| {
                let ca = unit_cost(a, w, cm, obj, cfg);
                let cb = unit_cost(b, w, cm, obj, cfg);
                ca.partial_cmp(&cb).unwrap()
            })
            .unwrap();
        sizes.push(best);
    }

    let mut rank: Vec<usize> = usable.clone();
    rank.sort_by(|&a, &b| {
        let ca = unit_cost(sizes[a], &view[a], cm, obj, cfg);
        let cb = unit_cost(sizes[b], &view[b], cm, obj, cfg);
        ca.partial_cmp(&cb).unwrap().then_with(|| {
            let ra = sizes[a] as f64
                / (cm.prove_ms_on(sizes[a], &view[a]) + cm.transfer_ms(sizes[a], &view[a]));
            let rb = sizes[b] as f64
                / (cm.prove_ms_on(sizes[b], &view[b]) + cm.transfer_ms(sizes[b], &view[b]));
            rb.partial_cmp(&ra).unwrap()
        })
    });
    if cfg.load_balancing {
        let mut best: Option<(f64, Plan, Vec<usize>)> = None;
        for j in 1..=rank.len() {
            let subset: Vec<usize> = rank[..j].to_vec();
            let sub_view: Vec<Worker> = subset.iter().map(|&i| view[i].clone()).collect();
            let sub_sizes: Vec<usize> = subset.iter().map(|&i| sizes[i]).collect();
            let sub_real: Vec<Worker> = subset.iter().map(|&i| workers[i].clone()).collect();
            let counts = water_fill(k, &sub_view, cm, &sub_sizes);
            let plan = materialise(&counts, &sub_sizes, &sub_real, cm);
            let c = evaluate(&plan, &view, cm, obj).objective;
            if best.as_ref().map(|(bc, _, _)| c < *bc).unwrap_or(true) {
                best = Some((c, plan, subset));
            }
        }
        let (mut best_cost, mut plan, mut subset) = {
            let (c, p, s) = best.expect("at least one worker");
            (c, p, s)
        };
        if k <= 4096 {
            let greedy = greedy_complete(k, &view, workers, cm, obj, cap, cfg);
            let gc = evaluate(&greedy, &view, cm, obj).objective;
            if gc < best_cost {
                best_cost = gc;
                plan = greedy;
                subset = usable.clone();
            }
        }
        for _ in 0..cfg.local_search_rounds {
            let mut improved = false;
            for &wi in &subset {
                let feas: Vec<usize> = cm
                    .sizes
                    .iter()
                    .cloned()
                    .filter(|&g| g <= cap && cm.peak_mb_on(g, &view[wi]) <= view[wi].mem_mb)
                    .collect();
                for g in feas {
                    if g == sizes[wi] {
                        continue;
                    }
                    let mut trial_sizes = sizes.clone();
                    trial_sizes[wi] = g;
                    let sub_view: Vec<Worker> = subset.iter().map(|&i| view[i].clone()).collect();
                    let sub_sizes: Vec<usize> = subset.iter().map(|&i| trial_sizes[i]).collect();
                    let sub_real: Vec<Worker> = subset.iter().map(|&i| workers[i].clone()).collect();
                    let counts = water_fill(k, &sub_view, cm, &sub_sizes);
                    let trial = materialise(&counts, &sub_sizes, &sub_real, cm);
                    let c = evaluate(&trial, &view, cm, obj).objective;
                    if c < best_cost - 1e-9 {
                        best_cost = c;
                        sizes = trial_sizes;
                        plan = trial;
                        improved = true;
                    }
                }
            }
            if let Some(better) = try_move_group(&plan, &view, cm, obj) {
                let c = evaluate(&better, &view, cm, obj).objective;
                if c < best_cost - 1e-9 {
                    best_cost = c;
                    plan = better;
                    improved = true;
                }
            }
            if !improved {
                break;
            }
        }
        return plan;
    }
    let counts = {
        let mut counts = vec![0usize; view.len()];
        let mut left = k;
        let mut i = 0;
        while left > 0 {
            let wi = usable[i % usable.len()];
            let g = sizes[wi].min(left);
            counts[wi] += g;
            left -= g;
            i += 1;
        }
        counts
    };

    let mut plan = materialise(&counts, &sizes, workers, cm);

    let mut best_cost = evaluate(&plan, &view, cm, obj).objective;
    for _ in 0..cfg.local_search_rounds {
        let mut improved = false;
        for wi in 0..view.len() {
            let feas: Vec<usize> = cm
                .sizes
                .iter()
                .cloned()
                .filter(|&g| g <= cap && cm.peak_mb_on(g, &view[wi]) <= view[wi].mem_mb)
                .collect();
            for g in feas {
                if g == sizes[wi] {
                    continue;
                }
                let mut trial_sizes = sizes.clone();
                trial_sizes[wi] = g;
                let trial = materialise(&counts, &trial_sizes, workers, cm);
                let c = evaluate(&trial, &view, cm, obj).objective;
                if c < best_cost - 1e-9 {
                    best_cost = c;
                    sizes = trial_sizes;
                    plan = trial;
                    improved = true;
                }
            }
        }
        if let Some(better) = try_move_group(&plan, &view, cm, obj) {
            let c = evaluate(&better, &view, cm, obj).objective;
            if c < best_cost - 1e-9 {
                best_cost = c;
                plan = better;
                improved = true;
            }
        }
        if !improved {
            break;
        }
    }
    plan
}

fn unit_cost(
    g: usize,
    w: &Worker,
    cm: &CostModel,
    obj: &Objective,
    cfg: &HeuristicConfig,
) -> f64 {
    let t = cm.prove_ms_on(g, w);
    let x = if cfg.network_aware { cm.transfer_ms(g, w) } else { 0.0 };
    let agg = if cfg.aggregation_aware { cm.agg_step_ms } else { 0.0 };
    let f = if cfg.failure_aware { w.failure_prob * (t + x) } else { 0.0 };
    (obj.latency(t + x + agg)
        + obj.storage(cm.proof_bytes_on(g, w))
        + obj.compute(t * w.cost_weight)
        + obj.communication(x)
        + obj.failure(f))
        / g as f64
}

#[allow(clippy::too_many_arguments)]
fn greedy_complete(
    k: usize,
    view: &[Worker],
    real: &[Worker],
    cm: &CostModel,
    obj: &Objective,
    cap: usize,
    cfg: &HeuristicConfig,
) -> Plan {
    let mut load: Vec<f64> = view.iter().map(|w| w.load_ms).collect();
    let mut engaged = vec![false; view.len()];
    let mut groups: Vec<(usize, usize)> = Vec::new();
    let mut left = k;
    while left > 0 {
        let cur_max = load
            .iter()
            .zip(&engaged)
            .filter_map(|(&finish, &used)| used.then_some(finish))
            .fold(0.0f64, f64::max);
        let mut best: Option<(f64, usize, usize)> = None;
        for (wi, w) in view.iter().enumerate() {
            for &g in &cm.sizes {
                if g > cap || cm.peak_mb_on(g, w) > w.mem_mb {
                    continue;
                }
                let s = g.min(left);
                let t = cm.prove_ms_on(s, w);
                let x = if cfg.network_aware { cm.transfer_ms(s, w) } else { 0.0 };
                let new_max = cur_max.max(load[wi] + t + x);
                let agg = if cfg.aggregation_aware { cm.agg_step_ms } else { 0.0 };
                let fail = if cfg.failure_aware { w.failure_prob * (t + x) } else { 0.0 };
                let delta = obj.score(
                    new_max - cur_max + agg,
                    cm.proof_bytes_on(s, w),
                    t * w.cost_weight,
                    x,
                    fail,
                );
                let per_tx = delta / s as f64;
                if best.as_ref().map(|(b, _, _)| per_tx < *b).unwrap_or(true) {
                    best = Some((per_tx, s, wi));
                }
            }
        }
        match best {
            Some((_, s, wi)) => {
                let w = &view[wi];
                engaged[wi] = true;
                load[wi] += cm.prove_ms_on(s, w) + cm.transfer_ms(s, w);
                groups.push((s, real[wi].id));
                left -= s;
            }
            None => break,
        }
    }
    Plan { groups, target_txs: k, circuit_budget: cm.circuit_budget }
}

fn water_fill(k: usize, workers: &[Worker], cm: &CostModel, sizes: &[usize]) -> Vec<usize> {
    let per_group: Vec<f64> = workers
        .iter()
        .zip(sizes)
        .map(|(w, &g)| cm.prove_ms_on(g, w) + cm.transfer_ms(g, w))
        .collect();
    let capacity = |t: f64| -> usize {
        workers
            .iter()
            .zip(sizes)
            .zip(&per_group)
            .map(|((w, &g), &c)| {
                let avail = (t - w.load_ms).max(0.0);
                ((avail / c).floor() as usize) * g
            })
            .sum()
    };
    let mut lo = 0.0f64;
    let mut hi = workers
        .iter()
        .zip(&per_group)
        .map(|(w, &c)| w.load_ms + c * k as f64)
        .fold(0.0f64, f64::max)
        .max(1.0);
    for _ in 0..60 {
        let mid = 0.5 * (lo + hi);
        if capacity(mid) >= k {
            hi = mid;
        } else {
            lo = mid;
        }
    }
    let mut counts: Vec<usize> = workers
        .iter()
        .zip(sizes)
        .zip(&per_group)
        .map(|((w, &g), &c)| {
            let avail = (hi - w.load_ms).max(0.0);
            ((avail / c).floor() as usize) * g
        })
        .collect();
    let mut total: usize = counts.iter().sum();
    while total > k {
        let (wi, _) = per_group
            .iter()
            .enumerate()
            .filter(|(i, _)| counts[*i] > 0)
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap())
            .unwrap();
        let g = sizes[wi];
        let cut = g.min(counts[wi]).min(total - k);
        counts[wi] -= cut;
        total -= cut;
        if cut == 0 {
            break;
        }
    }
    while total < k {
        let (wi, _) = per_group
            .iter()
            .enumerate()
            .min_by(|a, b| a.1.partial_cmp(b.1).unwrap())
            .unwrap();
        let add = sizes[wi].min(k - total);
        counts[wi] += add;
        total += add;
    }
    counts
}

fn materialise(counts: &[usize], sizes: &[usize], workers: &[Worker], cm: &CostModel) -> Plan {
    let mut groups = Vec::new();
    for (i, &c) in counts.iter().enumerate() {
        let g = sizes[i].max(1);
        let mut left = c;
        while left > 0 {
            let s = g.min(left);
            groups.push((s, workers[i].id));
            left -= s;
        }
    }
    let target_txs = groups.iter().map(|(g, _)| *g).sum();
    Plan { groups, target_txs, circuit_budget: cm.circuit_budget }
}

fn try_move_group(plan: &Plan, workers: &[Worker], cm: &CostModel, _obj: &Objective) -> Option<Plan> {
    let mut load = vec![0.0f64; workers.len()];
    let mut engaged = vec![false; workers.len()];
    for (i, w) in workers.iter().enumerate() {
        load[i] = w.load_ms;
    }
    let index: Vec<usize> = workers.iter().map(|w| w.id).collect();
    let pos = |id: usize| index.iter().position(|&x| x == id).unwrap();
    for &(g, wid) in &plan.groups {
        let i = pos(wid);
        engaged[i] = true;
        load[i] += cm.prove_ms_on(g, &workers[i]) + cm.transfer_ms(g, &workers[i]);
    }
    let busiest = (0..workers.len())
        .filter(|&i| engaged[i])
        .max_by(|&a, &b| load[a].partial_cmp(&load[b]).unwrap())?;
    let idlest = (0..workers.len())
        .min_by(|&a, &b| load[a].partial_cmp(&load[b]).unwrap())
        .unwrap();
    if busiest == idlest {
        return None;
    }
    let mut out = plan.clone();
    let j = out.groups.iter().rposition(|&(_, wid)| pos(wid) == busiest)?;
    let (g, _) = out.groups[j];
    if cm.peak_mb_on(g, &workers[idlest]) > workers[idlest].mem_mb {
        return None;
    }
    out.groups[j] = (g, workers[idlest].id);
    Some(out)
}

pub struct ExactResult {
    pub plan: Plan,
    pub cost: f64,
    pub nodes: u64,
    pub proved_optimal: bool,
}

pub fn plan_exact(
    k: usize,
    workers: &[Worker],
    cm: &CostModel,
    obj: &Objective,
    cap: usize,
    node_budget: u64,
) -> ExactResult {
    let sizes: Vec<usize> = cm.sizes.iter().cloned().filter(|&g| g <= cap).collect();
    let min_bytes_per_tx = sizes
        .iter()
        .flat_map(|&g| workers.iter().map(move |w| cm.proof_bytes_on(g, w) / g as f64))
        .fold(f64::INFINITY, f64::min);
    let min_compute_per_tx = sizes
        .iter()
        .flat_map(|&g| {
            workers
                .iter()
                .filter(move |w| cm.peak_mb_on(g, w) <= w.mem_mb)
                .map(move |w| cm.prove_ms_on(g, w) * w.cost_weight / g as f64)
        })
        .fold(f64::INFINITY, f64::min);
    let min_comm_per_tx = sizes
        .iter()
        .flat_map(|&g| {
            workers
                .iter()
                .filter(move |w| cm.peak_mb_on(g, w) <= w.mem_mb)
                .map(move |w| cm.transfer_ms(g, w) / g as f64)
        })
        .fold(f64::INFINITY, f64::min);
    let min_agg_per_tx = sizes
        .iter()
        .map(|&g| cm.agg_step_ms / g as f64)
        .fold(f64::INFINITY, f64::min);
    let total_rate: f64 = workers
        .iter()
        .map(|w| {
            sizes
                .iter()
                .filter(|&&g| cm.peak_mb_on(g, w) <= w.mem_mb)
                .map(|&g| g as f64 / (cm.prove_ms_on(g, w) + cm.transfer_ms(g, w)))
                .fold(0.0f64, f64::max)
        })
        .sum();

    let seed = plan_resource_aware(
        k,
        workers,
        cm,
        obj,
        cap,
        &HeuristicConfig::default(),
    );
    let seed_cost = evaluate(&seed, workers, cm, obj);
    let mut best_cost = if seed_cost.feasible { seed_cost.objective } else { f64::INFINITY };
    let mut best_plan = if seed_cost.feasible { seed } else { Plan::default() };
    let mut nodes: u64 = 0;
    let mut exhausted = true;

    struct State {
        load: Vec<f64>,
        engaged: Vec<bool>,
        stored: f64,
        compute: f64,
        comm: f64,
        fail: f64,
        groups: Vec<(usize, usize)>,
    }

    #[allow(clippy::too_many_arguments)]
    fn dfs(
        left: usize,
        st: &mut State,
        workers: &[Worker],
        cm: &CostModel,
        obj: &Objective,
        sizes: &[usize],
        lb_terms: (f64, f64, f64, f64, f64),
        nodes: &mut u64,
        budget: u64,
        best_cost: &mut f64,
        best_plan: &mut Plan,
        exhausted: &mut bool,
    ) {
        *nodes += 1;
        if *nodes > budget {
            *exhausted = false;
            return;
        }
        let (min_b, min_c, min_x, min_a, total_rate) = lb_terms;
        let limit = crate::pcc::MAX_BLOCK_GROUPS as usize;
        let largest = sizes.iter().copied().max().unwrap_or(0);
        if st.groups.len() > limit
            || left > limit.saturating_sub(st.groups.len()).saturating_mul(largest)
        {
            return;
        }
        if left == 0 {
            let makespan = st
                .load
                .iter()
                .zip(&st.engaged)
                .filter_map(|(&load, &used)| used.then_some(load))
                .fold(0.0f64, f64::max)
                + cm.aggregate_ms(st.groups.len());
            let j = obj.score(makespan, st.stored, st.compute, st.comm, st.fail);
            if j < *best_cost {
                *best_cost = j;
                *best_plan = Plan {
                    groups: st.groups.clone(),
                    target_txs: st.groups.iter().map(|(g, _)| *g).sum(),
                    circuit_budget: cm.circuit_budget,
                };
            }
            return;
        }
        let cur_max = st
            .load
            .iter()
            .zip(&st.engaged)
            .filter_map(|(&load, &used)| used.then_some(load))
            .fold(0.0f64, f64::max);
        let remaining_wall_lb = if total_rate > 0.0 { left as f64 / total_rate } else { 0.0 };
        let makespan_lb = cur_max.max(remaining_wall_lb) + cm.aggregate_ms(st.groups.len())
            + min_a * left as f64;
        let lb = obj.score(
            makespan_lb,
            st.stored + min_b * left as f64,
            st.compute + min_c * left as f64,
            st.comm + min_x * left as f64,
            st.fail,
        );
        if lb >= *best_cost {
            return;
        }
        let mut choices: Vec<usize> = sizes.iter().map(|g| (*g).min(left)).collect();
        choices.sort_unstable();
        choices.dedup();
        choices.reverse();
        for s in choices {
            for (wi, w) in workers.iter().enumerate() {
                if cm.peak_mb_on(s, w) > w.mem_mb {
                    continue;
                }
                let t = cm.prove_ms_on(s, w);
                let x = cm.transfer_ms(s, w);
                let was_engaged = st.engaged[wi];
                st.engaged[wi] = true;
                st.load[wi] += t + x;
                st.stored += cm.proof_bytes_on(s, w);
                st.compute += t * w.cost_weight;
                st.comm += x;
                st.fail += w.failure_prob * (t + x);
                st.groups.push((s, w.id));
                dfs(
                    left - s,
                    st,
                    workers,
                    cm,
                    obj,
                    sizes,
                    lb_terms,
                    nodes,
                    budget,
                    best_cost,
                    best_plan,
                    exhausted,
                );
                st.groups.pop();
                st.load[wi] -= t + x;
                st.stored -= cm.proof_bytes_on(s, w);
                st.compute -= t * w.cost_weight;
                st.comm -= x;
                st.fail -= w.failure_prob * (t + x);
                st.engaged[wi] = was_engaged;
                if *nodes > budget {
                    return;
                }
            }
        }
    }

    let mut st = State {
        load: workers.iter().map(|w| w.load_ms).collect(),
        engaged: vec![false; workers.len()],
        stored: 0.0,
        compute: 0.0,
        comm: 0.0,
        fail: 0.0,
        groups: Vec::new(),
    };
    dfs(
        k,
        &mut st,
        workers,
        cm,
        obj,
        &sizes,
        (min_bytes_per_tx, min_compute_per_tx, min_comm_per_tx, min_agg_per_tx, total_rate),
        &mut nodes,
        node_budget,
        &mut best_cost,
        &mut best_plan,
        &mut exhausted,
    );

    ExactResult { plan: best_plan, cost: best_cost, nodes, proved_optimal: exhausted }
}

#[allow(clippy::too_many_arguments)]
pub fn plan_hybrid(
    k: usize,
    workers: &[Worker],
    cm: &CostModel,
    obj: &Objective,
    cap: usize,
    cfg: &HeuristicConfig,
    exact_threshold: usize,
    node_budget: u64,
) -> Plan {
    if k <= exact_threshold {
        let ex = plan_exact(k, workers, cm, obj, cap, node_budget);
        if ex.proved_optimal && ex.cost.is_finite() {
            return ex.plan;
        }
    }
    plan_resource_aware(k, workers, cm, obj, cap, cfg)
}

pub fn reassign(
    outstanding: &[usize],
    workers: &[Worker],
    cm: &CostModel,
) -> Vec<(usize, usize)> {
    let mut load: Vec<f64> = workers.iter().map(|w| w.load_ms).collect();
    let mut out = Vec::with_capacity(outstanding.len());
    let mut order: Vec<usize> = (0..outstanding.len()).collect();
    order.sort_by(|&a, &b| outstanding[b].cmp(&outstanding[a]));
    for &oi in &order {
        let g = outstanding[oi];
        let pick = workers
            .iter()
            .enumerate()
            .filter(|(_, w)| cm.peak_mb_on(g, w) <= w.mem_mb)
            .min_by(|(i, wi), (j, wj)| {
                let a = load[*i] + cm.prove_ms_on(g, wi) + cm.transfer_ms(g, wi);
                let b = load[*j] + cm.prove_ms_on(g, wj) + cm.transfer_ms(g, wj);
                a.partial_cmp(&b).unwrap()
            });
        if let Some((wi, w)) = pick {
            load[wi] += cm.prove_ms_on(g, w) + cm.transfer_ms(g, w);
            out.push((g, w.id));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model() -> CostModel {
        CostModel {
            circuit_budget: 16,
            circuit_id: "test-circuit".into(),
            sizes: vec![1, 2, 4, 8, 16],
            prove_ms: vec![800.0, 1600.0, 3300.0, 6800.0, 14000.0],
            peak_mb: vec![700.0, 704.0, 698.0, 702.0, 701.0],
            proof_bytes: vec![127000.0, 131000.0, 137000.0, 145000.0, 155000.0],
            verify_ms: vec![5.0, 5.2, 5.5, 6.0, 6.5],
            agg_step_ms: 6000.0,
            agg_peak_mb: 860.0,
            witness_bytes_per_tx: 67.0 * 32.0,
        }
    }

    #[test]
    fn partition_covers_every_transaction() {
        let cm = model();
        let ws: Vec<Worker> = (0..4).map(|i| Worker::homogeneous(i, 1024.0)).collect();
        let p = plan_resource_aware(37, &ws, &cm, &Objective::default(), 16, &HeuristicConfig::default());
        assert_eq!(p.groups.iter().map(|(g, _)| g).sum::<usize>(), 37);
    }

    #[test]
    fn memory_awareness_prevents_violations() {
        let cm = model();
        let mut ws: Vec<Worker> = (0..3).map(|i| Worker::homogeneous(i, 1024.0)).collect();
        ws[2].mem_mb = 100.0;
        let obj = Objective::default();
        let aware = plan_resource_aware(24, &ws, &cm, &obj, 16, &HeuristicConfig::default());
        assert_eq!(evaluate(&aware, &ws, &cm, &obj).memory_violations, 0);
        let baseline = plan_max_fit(24, &ws, &cm, 16);
        assert_eq!(evaluate(&baseline, &ws, &cm, &obj).memory_violations, 0);
        assert!(baseline.groups.iter().all(|(_, wid)| *wid != 2));
    }

    #[test]
    fn exact_is_no_worse_than_heuristic() {
        let cm = model();
        let ws: Vec<Worker> = (0..2).map(|i| Worker::homogeneous(i, 1024.0)).collect();
        let obj = Objective::default();
        let ex = plan_exact(8, &ws, &cm, &obj, 8, 400_000);
        let he = plan_resource_aware(8, &ws, &cm, &obj, 8, &HeuristicConfig::default());
        let hc = evaluate(&he, &ws, &cm, &obj).objective;
        assert!(ex.cost <= hc + 1e-6, "exact {} must not exceed heuristic {}", ex.cost, hc);
        assert_eq!(ex.plan.groups.iter().map(|(g, _)| g).sum::<usize>(), 8);
    }

    #[test]
    fn exact_matches_independent_exhaustive_enumeration() {
        fn enumerate(
            left: usize, plan: &mut Plan, workers: &[Worker], cm: &CostModel,
            objective: &Objective, best: &mut f64,
        ) {
            if left == 0 {
                *best = best.min(evaluate(plan, workers, cm, objective).objective);
                return;
            }
            let mut choices: Vec<_> = cm.sizes.iter().map(|&n| n.min(left)).collect();
            choices.sort_unstable();
            choices.dedup();
            for n in choices {
                for worker in workers {
                    plan.groups.push((n, worker.id));
                    enumerate(left - n, plan, workers, cm, objective, best);
                    plan.groups.pop();
                }
            }
        }
        for sparse in [false, true] {
            for case in 0..12 {
                let mut cm = model();
                cm.circuit_budget = 4;
                cm.sizes = if sparse { vec![2, 4] } else { vec![1, 2, 3, 4] };
                cm.prove_ms = cm.sizes.iter().map(|&n| 17.0 + (case + 1) as f64 * n as f64).collect();
                cm.peak_mb = vec![700.0; cm.sizes.len()];
                cm.proof_bytes = cm.sizes.iter().map(|&n| 300.0 + 8.0 * n as f64).collect();
                cm.verify_ms = vec![2.0; cm.sizes.len()];
                cm.agg_step_ms = (case % 3) as f64 * 9.0;
                let mut workers = vec![Worker::homogeneous(0, 1024.0), Worker::homogeneous(1, 1024.0)];
                workers[0].load_ms = (case % 4) as f64 * 80.0;
                workers[0].failure_prob = 0.02;
                workers[1].failure_prob = 0.25;
                workers[1].cost_weight = 1.7;
                workers[1].latency_ms = (case % 3) as f64 * 7.0;
                workers[1].profile = Some(cm.reference_profile("enumeration"));
                for time in &mut workers[1].profile.as_mut().unwrap().prove_ms {
                    *time *= 0.5 + case as f64 / 8.0;
                }
                if case % 5 == 0 { workers[1].mem_mb = 100.0; }
                for k in 1..=7 {
                    let reference = evaluate(&plan_max_fit(k, &workers, &cm, 4), &workers, &cm, &Objective::default());
                    let mut objective = Objective::default().normalised_by(&reference);
                    objective.alpha = if case % 2 == 0 { 0.0 } else { 1.0 };
                    let mut best = f64::INFINITY;
                    let mut plan = Plan { groups: Vec::new(), target_txs: k, circuit_budget: 4 };
                    enumerate(k, &mut plan, &workers, &cm, &objective, &mut best);
                    let exact = plan_exact(k, &workers, &cm, &objective, 4, 1_000_000);
                    assert!(exact.proved_optimal);
                    assert!((exact.cost - best).abs() <= 1e-9 * best.max(1.0),
                        "case {case}, sparse {sparse}, k {k}: exact {} != exhaustive {best}", exact.cost);
                }
            }
        }
    }

    #[test]
    fn heterogeneity_awareness_helps() {
        let cm = model();
        let mut ws: Vec<Worker> = (0..4).map(|i| Worker::homogeneous(i, 1500.0)).collect();
        for w in &mut ws {
            w.profile = Some(cm.reference_profile(format!("worker-{}", w.id)));
        }
        for t in &mut ws[0].profile.as_mut().unwrap().prove_ms {
            *t *= 0.25;
        }
        for (i, t) in ws[3].profile.as_mut().unwrap().prove_ms.iter_mut().enumerate() {
            *t *= 3.0 + i as f64 * 0.2;
        }
        let obj = Objective::default();
        let aware = plan_resource_aware(32, &ws, &cm, &obj, 16, &HeuristicConfig::default());
        let mut blind_cfg = HeuristicConfig::default();
        blind_cfg.heterogeneity_aware = false;
        let blind = plan_resource_aware(32, &ws, &cm, &obj, 16, &blind_cfg);
        let a = evaluate(&aware, &ws, &cm, &obj);
        let b = evaluate(&blind, &ws, &cm, &obj);
        assert!(a.makespan_ms <= b.makespan_ms, "aware {a} should not be slower than blind {b}");
    }

    #[test]
    fn plan_contract_rejects_wrong_budget_coverage_and_occupancy() {
        let cm = model();
        let ws = vec![Worker::homogeneous(0, 1024.0)];
        let valid = Plan {
            groups: vec![(16, 0), (5, 0)],
            target_txs: 21,
            circuit_budget: 16,
        };
        assert!(validate_plan(&valid, &ws, &cm).is_ok());

        let mut wrong = valid.clone();
        wrong.circuit_budget = 8;
        assert!(validate_plan(&wrong, &ws, &cm).is_err());
        let mut wrong = valid.clone();
        wrong.target_txs = 22;
        assert!(validate_plan(&wrong, &ws, &cm).is_err());
        let mut wrong = valid;
        wrong.groups[1].0 = 17;
        assert!(validate_plan(&wrong, &ws, &cm).is_err());
    }

    #[test]
    fn plan_contract_enforces_inclusive_protocol_group_limit() {
        let cm = model();
        let ws = vec![Worker::homogeneous(0, 1024.0)];
        let limit = crate::pcc::MAX_BLOCK_GROUPS as usize;
        let mut plan = Plan {
            groups: vec![(1, 0); limit],
            target_txs: limit,
            circuit_budget: cm.circuit_budget,
        };
        assert!(validate_plan(&plan, &ws, &cm).is_ok());
        plan.groups.push((1, 0));
        plan.target_txs += 1;
        assert!(validate_plan(&plan, &ws, &cm).is_err());
        let cost = evaluate(&plan, &ws, &cm, &Objective::default());
        assert!(!cost.feasible);
        assert!(cost.objective.is_infinite());
        assert_eq!(cost.memory_violations, 0);
        let exact = plan_exact(limit + 1, &ws, &cm, &Objective::default(), 1, 1000);
        assert!(exact.proved_optimal);
        assert!(exact.cost.is_infinite());
    }

    #[test]
    fn short_group_does_not_fit_when_fixed_circuit_does_not_fit() {
        let cm = model();
        let ws = vec![Worker::homogeneous(0, 200.0)];
        let p = Plan {
            groups: vec![(1, 0)],
            target_txs: 1,
            circuit_budget: 16,
        };
        assert!(validate_plan(&p, &ws, &cm).is_err());
        assert!(!evaluate(&p, &ws, &cm, &Objective::default()).feasible);
    }

    #[test]
    fn disabling_load_balancing_keeps_memory_admission_active() {
        let cm = model();
        let mut ws = vec![
            Worker::homogeneous(0, 1024.0),
            Worker::homogeneous(1, 100.0),
        ];
        ws[0].load_ms = 200.0;
        let mut cfg = HeuristicConfig::default();
        cfg.load_balancing = false;
        let plan = plan_resource_aware(12, &ws, &cm, &Objective::default(), 16, &cfg);
        validate_plan(&plan, &ws, &cm).unwrap();
        assert!(plan.groups.iter().all(|(_, worker)| *worker == 0));
    }

    #[test]
    fn unassigned_worker_load_does_not_delay_a_plan() {
        let cm = model();
        let mut ws = vec![
            Worker::homogeneous(0, 1024.0),
            Worker::homogeneous(1, 1024.0),
        ];
        ws[1].load_ms = 1_000_000.0;
        let plan = Plan {
            groups: vec![(4, 0)],
            target_txs: 4,
            circuit_budget: 16,
        };
        let cost = evaluate(&plan, &ws, &cm, &Objective::default());
        let expected = cm.prove_ms_on(4, &ws[0]) + cm.transfer_ms(4, &ws[0]) + cm.agg_step_ms;
        assert!((cost.makespan_ms - expected).abs() < 1e-9);

        let exact = plan_exact(4, &ws, &cm, &Objective::default(), 16, 100_000);
        assert!(exact.proved_optimal);
        assert!(exact.plan.groups.iter().all(|(_, worker)| *worker == 0));
    }

    #[test]
    fn lst_capacity_plan_is_feasible_and_complete() {
        let cm = model();
        let mut ws = vec![Worker::homogeneous(0, 1024.0), Worker::homogeneous(1, 1024.0)];
        ws[0].load_ms = 500.0;
        let p = plan_lst_capacity(37, &ws, &cm, 16);
        validate_plan(&p, &ws, &cm).unwrap();
        assert_eq!(p.groups.iter().map(|(g, _)| *g).sum::<usize>(), 37);
        assert!(p.groups.iter().all(|(g, _)| *g <= 16));
    }

    #[test]
    fn fixed_circuit_loader_rejects_mixed_budgets() {
        let path =
            std::env::temp_dir().join(format!("pcb-mixed-budget-{}.csv", std::process::id()));
        let csv = concat!(
            "circuit_budget,occupancy,circuit_id,prove_ms,peak_mb,proof_bytes,verify_ms,",
            "agg_step_ms,agg_peak_mb\n",
            "2,1,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,1,2,3,4,5,6\n",
            "1,2,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,1,2,3,4,5,6\n",
        );
        std::fs::write(&path, csv).unwrap();
        let result = CostModel::from_fixed_circuit_csv(path.to_str().unwrap(), 2);
        let _ = std::fs::remove_file(path);
        assert!(result.is_err());
    }

    #[test]
    fn fixed_circuit_loader_rejects_nonfinite_metrics() {
        let path =
            std::env::temp_dir().join(format!("pcb-nonfinite-cost-{}.csv", std::process::id()));
        let csv = concat!(
            "circuit_budget,occupancy,circuit_id,prove_ms,peak_mb,proof_bytes,verify_ms,",
            "agg_step_ms,agg_peak_mb\n",
            "1,1,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,NaN,2,3,4,5,6\n",
        );
        std::fs::write(&path, csv).unwrap();
        let result = CostModel::from_fixed_circuit_csv(path.to_str().unwrap(), 1);
        let _ = std::fs::remove_file(path);
        assert!(result.is_err());
    }
}
