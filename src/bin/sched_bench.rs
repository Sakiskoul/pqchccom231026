use std::io::Write;
use std::time::Instant;

use pcb_recursive::sched::{
    evaluate, plan_earliest_finish, plan_equal_size, plan_exact, plan_greedy_marginal, plan_heft,
    plan_hybrid, plan_lst_capacity, plan_max_fit, plan_max_min, plan_min_min,
    plan_one_per_group, plan_resource_aware, CostModel, HeuristicConfig, Objective, PlanCost, Worker,
};

fn fleet(kind: &str, n: usize, mem_level: f64, cm: &CostModel) -> Vec<Worker> {
    (0..n)
        .map(|i| {
            let mut w = Worker::homogeneous(i, mem_level);
            w.profile = Some(cm.reference_profile(format!("synthetic-{kind}-{i}")));
            match kind {
                "homogeneous" => {}
                "heterogeneous" => {
                    let profile = w.profile.as_mut().unwrap();
                    let denom = cm.circuit_budget.saturating_sub(1).max(1) as f64;
                    for (j, t) in profile.prove_ms.iter_mut().enumerate() {
                        let x = j as f64 / denom;
                        let factor = match i % 4 {
                            0 => 0.55 + 0.20 * x,
                            1 => 0.95 + 0.15 * x,
                            2 => 1.80 - 0.40 * x,
                            _ => 0.75 + 0.35 * x,
                        };
                        *t *= factor;
                    }
                    let class = match i % 4 {
                        0 => 1.8,
                        1 => 1.0,
                        2 => 0.55,
                        _ => 1.35,
                    };
                    w.mem_mb = mem_level * class;
                    w.cost_weight = 1.0 / class;
                }
                "memory-skewed" => {
                    w.mem_mb = if i % 3 == 0 { mem_level / 8.0 } else { mem_level };
                }
                "unreliable" => {
                    w.failure_prob = if i % 4 == 0 { 0.25 } else { 0.02 };
                }
                "wan" => {
                    w.latency_ms = if i % 2 == 0 { 1.0 } else { 40.0 };
                    w.bandwidth_mbps = if i % 2 == 0 { 1000.0 } else { 20.0 };
                }
                _ => {}
            }
            w
        })
        .collect()
}

fn row(c: &PlanCost) -> String {
    format!(
        "{:.6},{:.0},{:.1},{:.1},{:.1},{:.1},{},{},{:.0},{:.3},{},{}",
        c.objective,
        c.stored_bytes,
        c.makespan_ms,
        c.compute_ms,
        c.comm_ms,
        c.failure_ms,
        c.num_groups,
        c.memory_violations,
        c.max_peak_mb,
        c.imbalance,
        c.feasible,
        c.coverage_txs
    )
}

fn objective_for(k: usize, workers: &[Worker], cm: &CostModel, cap: usize) -> Objective {
    let raw = Objective::default();
    let reference_plan = plan_max_fit(k, workers, cm, cap);
    let reference = evaluate(&reference_plan, workers, cm, &raw);
    if reference.feasible {
        raw.normalised_by(&reference)
    } else {
        raw
    }
}

pub const EXACT_THRESHOLD: usize = 16;

const COST_COLS: &str =
    "objective,stored_bytes,makespan_ms,compute_ms,comm_ms,failure_ms,groups,mem_violations,max_peak_mb,imbalance,feasible,coverage_txs";

fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().collect();
    let out = a.get(1).cloned().unwrap_or_else(|| "results".into());
    let model_path = a.get(2).cloned().unwrap_or_else(|| format!("{out}/group_cost.csv"));
    let circuit_budget: usize = a.get(3).and_then(|s| s.parse().ok()).unwrap_or(4);
    std::fs::create_dir_all(&out)?;
    let cm = CostModel::from_fixed_circuit_csv(&model_path, circuit_budget)?;
    let cap = *cm.sizes.iter().max().unwrap_or(&16);

    let mut f = std::fs::File::create(format!("{out}/sched_compare.csv"))?;
    writeln!(f, "fleet,workers,mem_mb,k,scheduler,{COST_COLS},plan_ms")?;
    let ks = [16usize, 32, 64, 128, 256, 512, 1024];
    let fleets = ["homogeneous", "heterogeneous", "memory-skewed", "unreliable", "wan"];
    let mems = [512.0f64, 1024.0, 4096.0];
    for &fk in &fleets {
        for &n in &[1usize, 2, 4, 8, 16] {
            for &mem in &mems {
                let ws = fleet(fk, n, mem, &cm);
                for &k in &ks {
                    let obj = objective_for(k, &ws, &cm, cap);
                    let mut plans: Vec<(&str, _, f64)> = Vec::new();
                    let t = Instant::now();
                    let p = plan_max_fit(k, &ws, &cm, cap);
                    plans.push(("feasible-max-fit", p, t.elapsed().as_secs_f64() * 1000.0));
                    let t = Instant::now();
                    let p = plan_equal_size(k, &ws, &cm, cap);
                    plans.push(("equal-size", p, t.elapsed().as_secs_f64() * 1000.0));
                    let t = Instant::now();
                    let p = plan_one_per_group(k, &ws, &cm);
                    plans.push(("one-per-tx", p, t.elapsed().as_secs_f64() * 1000.0));
                    let t = Instant::now();
                    let p = plan_earliest_finish(k, &ws, &cm, cap);
                    plans.push(("earliest-finish", p, t.elapsed().as_secs_f64() * 1000.0));
                    let t = Instant::now();
                    let p = plan_min_min(k, &ws, &cm, cap);
                    plans.push(("min-min", p, t.elapsed().as_secs_f64() * 1000.0));
                    let t = Instant::now();
                    let p = plan_max_min(k, &ws, &cm, cap);
                    plans.push(("max-min", p, t.elapsed().as_secs_f64() * 1000.0));
                    let t = Instant::now();
                    let p = plan_heft(k, &ws, &cm, cap);
                    plans.push(("heft", p, t.elapsed().as_secs_f64() * 1000.0));
                    let t = Instant::now();
                    let p = plan_lst_capacity(k, &ws, &cm, cap);
                    plans.push(("lst-capacity", p, t.elapsed().as_secs_f64() * 1000.0));
                    let t = Instant::now();
                    let p = plan_greedy_marginal(k, &ws, &cm, &obj, cap);
                    plans.push(("greedy-marginal", p, t.elapsed().as_secs_f64() * 1000.0));
                    let t = Instant::now();
                    let p = plan_resource_aware(k, &ws, &cm, &obj, cap, &HeuristicConfig::default());
                    plans.push(("resource-aware", p, t.elapsed().as_secs_f64() * 1000.0));
                    let t = Instant::now();
                    let p = plan_hybrid(
                        k, &ws, &cm, &obj, cap, &HeuristicConfig::default(), EXACT_THRESHOLD,
                        3_000_000,
                    );
                    plans.push(("hybrid", p, t.elapsed().as_secs_f64() * 1000.0));
                    for (name, plan, ms) in plans {
                        let c = evaluate(&plan, &ws, &cm, &obj);
                        writeln!(f, "{fk},{n},{mem},{k},{name},{},{ms:.4}", row(&c))?;
                    }
                }
            }
        }
    }
    eprintln!("wrote sched_compare.csv");
    if std::env::var("PCB_SCHED_COMPARE_ONLY").as_deref() == Ok("1") {
        return Ok(());
    }

    let mut f = std::fs::File::create(format!("{out}/sched_optgap.csv"))?;
    writeln!(
        f,
        "fleet,workers,mem_mb,k,reference_kind,reference_objective,heuristic_objective,proved_gap_pct,incumbent_gap_pct,exact_nodes,exact_proved_optimal,exact_ms,heuristic_ms"
    )?;
    for &fk in &["homogeneous", "heterogeneous", "memory-skewed"] {
        for &n in &[2usize, 3, 4] {
            for &mem in &[512.0f64, 4096.0] {
                let ws = fleet(fk, n, mem, &cm);
                for k in 1..=40usize {
                    let obj = objective_for(k, &ws, &cm, cap);
                    let t = Instant::now();
                    let ex = plan_exact(k, &ws, &cm, &obj, cap, 20_000_000);
                    let ems = t.elapsed().as_secs_f64() * 1000.0;
                    if !ex.cost.is_finite() {
                        continue;
                    }
                    let t = Instant::now();
                    let he =
                        plan_resource_aware(k, &ws, &cm, &obj, cap, &HeuristicConfig::default());
                    let hms = t.elapsed().as_secs_f64() * 1000.0;
                    let hc = evaluate(&he, &ws, &cm, &obj).objective;
                    let gap = 100.0 * (hc - ex.cost) / ex.cost;
                    let reference_kind =
                        if ex.proved_optimal { "proved-optimum" } else { "bnb-incumbent" };
                    let proved_gap = if ex.proved_optimal {
                        format!("{gap:.3}")
                    } else {
                        String::new()
                    };
                    writeln!(
                        f,
                        "{fk},{n},{mem},{k},{reference_kind},{:.3},{:.3},{proved_gap},{gap:.3},{},{},{ems:.2},{hms:.4}",
                        ex.cost, hc, ex.nodes, ex.proved_optimal
                    )?;
                }
            }
        }
    }
    eprintln!("wrote sched_optgap.csv");

    let mut f = std::fs::File::create(format!("{out}/sched_ablation.csv"))?;
    writeln!(f, "fleet,workers,mem_mb,k,ablation,{COST_COLS}")?;
    let ablations: Vec<(&str, HeuristicConfig)> = vec![
        ("full", HeuristicConfig::default()),
        (
            "no-memory-awareness",
            HeuristicConfig { memory_aware: false, ..HeuristicConfig::default() },
        ),
        (
            "no-heterogeneity",
            HeuristicConfig { heterogeneity_aware: false, ..HeuristicConfig::default() },
        ),
        ("no-network", HeuristicConfig { network_aware: false, ..HeuristicConfig::default() }),
        (
            "no-aggregation-cost",
            HeuristicConfig { aggregation_aware: false, ..HeuristicConfig::default() },
        ),
        (
            "no-failure-awareness",
            HeuristicConfig { failure_aware: false, ..HeuristicConfig::default() },
        ),
        (
            "no-load-balancing",
            HeuristicConfig { load_balancing: false, ..HeuristicConfig::default() },
        ),
        (
            "no-local-search",
            HeuristicConfig { local_search_rounds: 0, ..HeuristicConfig::default() },
        ),
    ];
    for &fk in &fleets {
        for &n in &[4usize, 8, 16] {
            for &mem in &[512.0f64, 4096.0] {
                let ws = fleet(fk, n, mem, &cm);
                for &k in &[64usize, 256, 1024] {
                    let obj = objective_for(k, &ws, &cm, cap);
                    for (name, cfg) in &ablations {
                        let p = plan_resource_aware(k, &ws, &cm, &obj, cap, cfg);
                        let c = evaluate(&p, &ws, &cm, &obj);
                        writeln!(f, "{fk},{n},{mem},{k},{name},{}", row(&c))?;
                    }
                }
            }
        }
    }
    eprintln!("wrote sched_ablation.csv");

    let mut f = std::fs::File::create(format!("{out}/sched_exact_scaling.csv"))?;
    writeln!(f, "fleet,workers,k,exact_ms,nodes,proved_optimal")?;
    'outer: for &fk in &["homogeneous", "heterogeneous"] {
        for &n in &[2usize, 4] {
            let ws = fleet(fk, n, 2048.0, &cm);
            for k in 1..=256usize {
                let obj = objective_for(k, &ws, &cm, cap);
                let t = Instant::now();
                let ex = plan_exact(k, &ws, &cm, &obj, cap, 20_000_000);
                let ms = t.elapsed().as_secs_f64() * 1000.0;
                writeln!(f, "{fk},{n},{k},{ms:.3},{},{}", ex.nodes, ex.proved_optimal)?;
                if ms > 2000.0 {
                    break;
                }
                if ms > 60_000.0 {
                    break 'outer;
                }
            }
        }
    }
    eprintln!("wrote sched_exact_scaling.csv");

    let mut f = std::fs::File::create(format!("{out}/sched_scalability.csv"))?;
    writeln!(f, "workers,k,plan_ms,groups")?;
    for &n in &[4usize, 16, 64, 256] {
        let ws = fleet("heterogeneous", n, 2048.0, &cm);
        for &k in &[64usize, 256, 1024, 4096, 16384, 65536] {
            let obj = objective_for(k, &ws, &cm, cap);
            let t = Instant::now();
            let p = plan_resource_aware(k, &ws, &cm, &obj, cap, &HeuristicConfig::default());
            writeln!(
                f,
                "{n},{k},{:.4},{}",
                t.elapsed().as_secs_f64() * 1000.0,
                p.groups.len()
            )?;
        }
    }
    eprintln!("wrote sched_scalability.csv");

    let sensitivity_workers = fleet("heterogeneous", 8, 2048.0, &cm);
    let sensitivity_k = 256usize;
    let base = objective_for(sensitivity_k, &sensitivity_workers, &cm, cap);
    let alpha_values = [0.25f64, 0.5, 1.0, 2.0, 4.0];
    let other_values = [0.0f64, 0.25, 0.5, 1.0, 2.0];
    let mut cases: Vec<(String, String, String, f64, Objective, Vec<Worker>, String)> = Vec::new();
    let mut grid_index = 0usize;
    for &alpha in &alpha_values {
        for &beta in &other_values {
            for &gamma in &other_values {
                for &delta in &other_values {
                    for &epsilon in &other_values {
                        let mut objective = base;
                        objective.alpha = alpha;
                        objective.beta = beta;
                        objective.gamma = gamma;
                        objective.delta = delta;
                        objective.eps = epsilon;
                        cases.push((
                            format!("grid-{grid_index:04}"),
                            "heterogeneous-model".into(),
                            "grid".into(),
                            f64::NAN,
                            objective,
                            sensitivity_workers.clone(),
                            "full-grid".into(),
                        ));
                        grid_index += 1;
                    }
                }
            }
        }
    }
    debug_assert_eq!(grid_index, 3125);
    let mut low_memory_workers = fleet("heterogeneous", 8, 512.0, &cm);
    for w in low_memory_workers.iter_mut().skip(4) {
        w.mem_mb = cm.peak_mb_of(1) - 1.0;
    }
    for (label, deployment, workers, weights) in [
        (
            "latency-dominant",
            "heterogeneous-model",
            sensitivity_workers.clone(),
            [4.0, 0.25, 0.25, 0.25, 0.25],
        ),
        (
            "storage-dominant",
            "heterogeneous-model",
            sensitivity_workers.clone(),
            [1.0, 2.0, 0.25, 0.25, 0.25],
        ),
        (
            "compute-dominant",
            "heterogeneous-model",
            sensitivity_workers.clone(),
            [1.0, 0.25, 2.0, 0.25, 0.25],
        ),
        (
            "wide-area",
            "heterogeneous-wide-area",
            fleet("wan", 8, 2048.0, &cm),
            [1.0, 0.25, 0.25, 2.0, 0.25],
        ),
        (
            "failure-prone",
            "heterogeneous-failure-prone",
            fleet("unreliable", 8, 2048.0, &cm),
            [1.0, 0.25, 0.25, 0.25, 2.0],
        ),
        (
            "strict-low-memory",
            "four-eligible-four-below-budget",
            low_memory_workers,
            [1.0, 0.25, 0.25, 0.25, 0.25],
        ),
    ] {
        let mut objective = objective_for(sensitivity_k, &workers, &cm, cap);
        [objective.alpha, objective.beta, objective.gamma, objective.delta, objective.eps] = weights;
        cases.push((
            label.into(),
            deployment.into(),
            "scenario".into(),
            f64::NAN,
            objective,
            workers,
            "deployment-scenario".into(),
        ));
    }

    let mut sensitivity = Vec::new();
    for (label, deployment, varied, value, objective, workers, pareto_scope) in cases {
        let plan = plan_resource_aware(
            sensitivity_k,
            &workers,
            &cm,
            &objective,
            cap,
            &HeuristicConfig::default(),
        );
        let cost = evaluate(&plan, &workers, &cm, &objective);
        sensitivity.push((label, deployment, varied, value, objective, plan, cost, pareto_scope));
    }
    let dominates = |a: &PlanCost, b: &PlanCost| {
        let av = [a.makespan_ms, a.stored_bytes, a.compute_ms, a.comm_ms, a.failure_ms];
        let bv = [b.makespan_ms, b.stored_bytes, b.compute_ms, b.comm_ms, b.failure_ms];
        av.iter().zip(bv).all(|(x, y)| x <= &y) && av.iter().zip(bv).any(|(x, y)| x < &y)
    };
    let pareto: Vec<bool> = (0..sensitivity.len())
        .map(|i| {
            sensitivity[i].7 == "full-grid"
                && !(0..sensitivity.len()).any(|j| {
                    j != i
                        && sensitivity[j].7 == "full-grid"
                        && dominates(&sensitivity[j].6, &sensitivity[i].6)
                })
        })
        .collect();
    let mut f = std::fs::File::create(format!("{out}/sched_objective_sensitivity.csv"))?;
    writeln!(
        f,
        "label,deployment,varied_weight,varied_value,alpha,beta,gamma,delta,epsilon,pareto_scope,pareto,{COST_COLS},plan"
    )?;
    for ((label, deployment, varied, value, objective, plan, cost, pareto_scope), is_pareto) in
        sensitivity.into_iter().zip(pareto)
    {
        let plan_text = plan
            .groups
            .iter()
            .map(|(g, w)| format!("{g}@{w}"))
            .collect::<Vec<_>>()
            .join("+");
        writeln!(
            f,
            "{label},{deployment},{varied},{value},{},{},{},{},{},{pareto_scope},{is_pareto},{},{}",
            objective.alpha,
            objective.beta,
            objective.gamma,
            objective.delta,
            objective.eps,
            row(&cost),
            plan_text
        )?;
    }
    eprintln!("wrote sched_objective_sensitivity.csv");
    Ok(())
}
