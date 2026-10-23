use std::collections::HashMap;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pcb_recursive::mem::peak_working_set_mb;
use pcb_recursive::net::{
    read_frame, write_frame, Hello, Task, TaskResult, TAG_HELLO, TAG_RESULT, TAG_SHUTDOWN, TAG_TASK,
};
use pcb_recursive::pcc::{
    block_id, build_block_circuit_with_fan_in, build_group_circuit, fold_acc, group_circuit_id,
    group_digest, make_block, zero_hash, GroupMode, Tx, C, D, F, GPI_BLOCK_ID, GPI_CIRCUIT_ID,
    GPI_GROUP_BUDGET, GPI_GROUP_DIGEST, GPI_GROUP_INDEX, GPI_TX_COUNT, MAX_BLOCK_GROUPS,
};
use pcb_recursive::sched::{
    evaluate, plan_earliest_finish, plan_equal_size, plan_greedy_marginal, plan_heft,
    plan_lst_capacity, plan_max_fit, plan_max_min, plan_min_min, plan_one_per_group,
    plan_resource_aware, validate_plan, CostModel, HeuristicConfig, Objective, Worker,
};
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::hash_types::HashOut;
use plonky2::plonk::proof::ProofWithPublicInputs;

type Proof = ProofWithPublicInputs<F, C, D>;

fn arg(args: &[String], key: &str) -> Option<String> {
    args.iter()
        .position(|a| a == key)
        .and_then(|i| args.get(i + 1).cloned())
}
fn argf(args: &[String], key: &str, d: f64) -> f64 {
    arg(args, key).and_then(|s| s.parse().ok()).unwrap_or(d)
}
fn argu(args: &[String], key: &str, d: usize) -> usize {
    arg(args, key).and_then(|s| s.parse().ok()).unwrap_or(d)
}
fn arglist(args: &[String], key: &str, n: usize, d: f64) -> Vec<f64> {
    let raw = arg(args, key).unwrap_or_default();
    let mut v: Vec<f64> = raw
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    if v.is_empty() {
        v.push(d);
    }
    while v.len() < n {
        v.push(*v.last().unwrap());
    }
    v.truncate(n);
    v
}

fn argstrlist(args: &[String], key: &str, n: usize) -> Vec<String> {
    let Some(raw) = arg(args, key) else {
        return Vec::new();
    };
    let mut v: Vec<String> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if v.is_empty() {
        return v;
    }
    while v.len() < n {
        v.push(v.last().unwrap().clone());
    }
    v.truncate(n);
    v
}

#[cfg(unix)]
fn process_cpu_ms() -> Option<f64> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let after_comm = stat.rsplit_once(')')?.1.trim();
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    let user_ticks: f64 = fields.get(11)?.parse().ok()?;
    let system_ticks: f64 = fields.get(12)?.parse().ok()?;
    let output = Command::new("getconf").arg("CLK_TCK").output().ok()?;
    let ticks_per_second: f64 = String::from_utf8(output.stdout).ok()?.trim().parse().ok()?;
    Some(1000.0 * (user_ticks + system_ticks) / ticks_per_second)
}

#[cfg(not(unix))]
fn process_cpu_ms() -> Option<f64> {
    None
}

fn load_cost_model(path: &str, circuit_budget: usize) -> anyhow::Result<CostModel> {
    CostModel::from_fixed_circuit_csv(path, circuit_budget)
}

#[cfg(unix)]
fn allowed_cpu_ids() -> Vec<usize> {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return Vec::new();
    };
    let Some(spec) = status
        .lines()
        .find_map(|line| line.strip_prefix("Cpus_allowed_list:"))
    else {
        return Vec::new();
    };
    let mut cpus = Vec::new();
    for part in spec.trim().split(',') {
        let mut bounds = part
            .split('-')
            .filter_map(|value| value.parse::<usize>().ok());
        let Some(start) = bounds.next() else {
            continue;
        };
        let end = bounds.next().unwrap_or(start);
        cpus.extend(start..=end);
    }
    cpus
}

#[cfg(unix)]
fn cpu_topology() -> Vec<(usize, usize, usize)> {
    let Ok(output) = Command::new("lscpu").arg("-p=CPU,CORE,SOCKET").output() else {
        return Vec::new();
    };
    let mut topology = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if line.starts_with('#') {
            continue;
        }
        let values: Vec<_> = line.split(',').collect();
        if values.len() != 3 {
            continue;
        }
        let (Ok(cpu), Ok(core), Ok(socket)) = (
            values[0].parse::<usize>(),
            values[1].parse::<usize>(),
            values[2].parse::<usize>(),
        ) else {
            continue;
        };
        topology.push((cpu, core, socket));
    }
    topology
}

#[cfg(unix)]
fn topology_by_core() -> Vec<Vec<usize>> {
    let allowed: std::collections::HashSet<usize> = allowed_cpu_ids().into_iter().collect();
    let mut by_core: std::collections::BTreeMap<(usize, usize), Vec<usize>> =
        std::collections::BTreeMap::new();
    for (cpu, core, socket) in cpu_topology() {
        if allowed.contains(&cpu) {
            by_core.entry((socket, core)).or_default().push(cpu);
        }
    }
    let mut cores: Vec<Vec<usize>> = by_core.into_values().collect();
    for siblings in &mut cores {
        siblings.sort_unstable();
    }
    cores
}

#[cfg(unix)]
fn physical_cpu_ids() -> Vec<usize> {
    topology_by_core()
        .into_iter()
        .filter_map(|siblings| siblings.into_iter().next())
        .collect()
}

fn physical_first_cpu_order(cores: &[Vec<usize>]) -> Vec<usize> {
    let rounds = cores.iter().map(Vec::len).max().unwrap_or(0);
    let mut cpus = Vec::new();
    for sibling_index in 0..rounds {
        for siblings in cores {
            if let Some(cpu) = siblings.get(sibling_index) {
                cpus.push(*cpu);
            }
        }
    }
    cpus
}

#[cfg(unix)]
fn logical_cpu_ids() -> Vec<usize> {
    let cores = topology_by_core();
    physical_first_cpu_order(&cores)
}

struct TaskSpec {
    id: usize,
    group_index: u64,
    size: usize,
    txs: Vec<Tx>,
    sigs: Vec<Vec<HashOut<F>>>,
    planned_worker: usize,
    digest: HashOut<F>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IncomingResultKind {
    Duplicate,
    Expected,
    Unexpected,
}

fn classify_incoming_result(
    task_already_done: bool,
    expected: Option<(usize, usize)>,
    task: usize,
    attempt: usize,
) -> IncomingResultKind {
    if task_already_done {
        IncomingResultKind::Duplicate
    } else if expected == Some((task, attempt)) {
        IncomingResultKind::Expected
    } else {
        IncomingResultKind::Unexpected
    }
}

fn note_first_failure(
    first_failure_at: &mut Option<f64>,
    recovery_task: &mut Option<usize>,
    task: usize,
    detected_at: f64,
) {
    if first_failure_at.is_none() {
        *first_failure_at = Some(detected_at);
        *recovery_task = Some(task);
    }
}

fn note_replacement(
    recovery_task: Option<usize>,
    recovered_at: &mut Option<f64>,
    task: usize,
    accepted_at: f64,
) -> bool {
    if recovered_at.is_none() && recovery_task == Some(task) {
        *recovered_at = Some(accepted_at);
        true
    } else {
        false
    }
}

fn pick_worker(
    group_size: usize,
    planned_worker: usize,
    alive: &[bool],
    busy: &[bool],
    workers: &[Worker],
    cm: &CostModel,
) -> Option<usize> {
    if let Some(planned) = workers.iter().position(|worker| worker.id == planned_worker) {
        if alive[planned] {
            return (!busy[planned]
                && cm.peak_mb_on(group_size, &workers[planned]) <= workers[planned].mem_mb)
                .then_some(planned);
        }
    }

    (0..workers.len())
        .filter(|&i| {
            alive[i] && !busy[i] && cm.peak_mb_on(group_size, &workers[i]) <= workers[i].mem_mb
        })
        .min_by(|&a, &b| {
            let ca = cm.prove_ms_on(group_size, &workers[a])
                + cm.transfer_ms(group_size, &workers[a]);
            let cb = cm.prove_ms_on(group_size, &workers[b])
                + cm.transfer_ms(group_size, &workers[b]);
            ca.partial_cmp(&cb).unwrap()
        })
}

fn main() -> anyhow::Result<()> {
    let cold_start = Instant::now();
    let run_start_unix_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let args: Vec<String> = std::env::args().collect();
    let k = argu(&args, "--k", 16);
    let g = argu(&args, "--g", 4);
    let nworkers = argu(&args, "--workers", 2);
    let block_fan_in = argu(&args, "--block-fan-in", 1);
    anyhow::ensure!(
        (1..=2).contains(&block_fan_in),
        "block fan-in must be one or two"
    );
    let worker_affinity_policy =
        arg(&args, "--worker-affinity").unwrap_or_else(|| "physical".into());
    anyhow::ensure!(
        matches!(worker_affinity_policy.as_str(), "physical" | "logical"),
        "worker affinity must be physical or logical"
    );
    let scheduler = arg(&args, "--scheduler").unwrap_or_else(|| "resource".into());
    let fault = arg(&args, "--fault").unwrap_or_else(|| "none".into());
    let latency_ms = argf(&args, "--latency-ms", 0.0);
    let bandwidth = argf(&args, "--bandwidth-mbps", f64::INFINITY);
    let timeout_ms = argf(&args, "--timeout-ms", 120_000.0);
    let timeout_factor = argf(&args, "--timeout-factor", 3.0);
    let duplicate_grace_ms = argf(&args, "--duplicate-grace-ms", 0.0);
    let recalibrate_threshold = argf(&args, "--recalibrate-threshold", 0.20);
    let tag = arg(&args, "--tag").unwrap_or_else(|| "run".into());
    let repetition = argu(&args, "--rep", 1);
    let node_label = arg(&args, "--node-label").unwrap_or_else(|| "single-host".into());
    let tasks_csv = arg(&args, "--tasks-csv");
    let summary_csv = arg(&args, "--summary-csv");
    let e2e_csv = arg(&args, "--e2e-csv");
    let chain_in = arg(&args, "--chain-in");
    let chain_out = arg(&args, "--chain-out");
    let chain_height = argu(&args, "--chain-height", 1) as u64;
    anyhow::ensure!(e2e_csv.is_some() == chain_out.is_some(), "e2e-csv and chain-out must be used together");
    anyhow::ensure!(chain_in.is_none() || e2e_csv.is_some(), "chain-in requires e2e mode");
    if let Some(path) = &chain_out {
        anyhow::ensure!(!std::path::Path::new(path).exists(), "chain output already exists");
    }
    let mems = arglist(&args, "--mem", nworkers, 4096.0);
    let worker_latencies = arglist(&args, "--worker-latency-ms", nworkers, latency_ms);
    let worker_bandwidths = arglist(
        &args, "--worker-bandwidth-mbps", nworkers,
        if bandwidth.is_finite() { bandwidth } else { 1000.0 },
    );
    let worker_profile_paths = argstrlist(&args, "--worker-profiles", nworkers);
    let seed = argu(&args, "--seed", 42) as u64;
    let port = argu(&args, "--port", 9099);
    let cost_model_path =
        arg(&args, "--cost-model").unwrap_or_else(|| "group_cost.csv".into());

    anyhow::ensure!(k > 0, "block size must be positive");
    anyhow::ensure!(
        (1..=4096).contains(&g),
        "group budget is outside protocol limits"
    );
    anyhow::ensure!(nworkers > 0, "at least one worker is required");
    anyhow::ensure!(
        (1..=u16::MAX as usize).contains(&port),
        "port is outside the TCP range"
    );
    anyhow::ensure!(
        latency_ms.is_finite() && latency_ms >= 0.0,
        "link latency must be finite and non-negative"
    );
    anyhow::ensure!(
        !bandwidth.is_nan() && bandwidth > 0.0,
        "link bandwidth must be positive"
    );
    anyhow::ensure!(
        timeout_ms.is_finite() && timeout_ms > 0.0,
        "timeout must be finite and positive"
    );
    anyhow::ensure!(
        timeout_factor.is_finite() && timeout_factor >= 1.0,
        "timeout factor must be finite and at least one"
    );
    anyhow::ensure!(
        duplicate_grace_ms.is_finite() && duplicate_grace_ms >= 0.0,
        "duplicate grace period must be finite and non-negative"
    );
    anyhow::ensure!(
        recalibrate_threshold.is_finite() && recalibrate_threshold >= 0.0,
        "recalibration threshold must be finite and non-negative"
    );
    anyhow::ensure!(
        mems.iter().all(|value| value.is_finite() && *value > 0.0),
        "every worker memory budget must be finite and positive"
    );
    anyhow::ensure!(worker_latencies.iter().all(|v| v.is_finite() && *v >= 0.0), "invalid worker latency");
    anyhow::ensure!(worker_bandwidths.iter().all(|v| v.is_finite() && *v > 0.0), "invalid worker bandwidth");

    let cm = load_cost_model(&cost_model_path, g)?;
    let deployed_circuit_id = group_circuit_id(g, GroupMode::Wots);
    let deployed_circuit_id_hex = deployed_circuit_id
        .elements
        .iter()
        .map(|element| format!("{:016x}", element.to_canonical_u64()))
        .collect::<String>();
    anyhow::ensure!(
        cm.circuit_id == deployed_circuit_id_hex,
        "cost model circuit identifier does not match the deployed group circuit"
    );
    let bb = make_block(seed, k, g);
    let all_txs: Vec<Tx> = bb.groups.iter().flatten().cloned().collect();
    let all_sigs: Vec<Vec<HashOut<F>>> = bb.sigs.iter().flatten().cloned().collect();

    let mut planner_workers: Vec<Worker> = Vec::with_capacity(nworkers);
    for i in 0..nworkers {
        let mut w = Worker::homogeneous(i, mems[i]);
        w.profile = if worker_profile_paths.is_empty() {
            Some(cm.reference_profile(format!("{cost_model_path}#reference")))
        } else {
            let p = &worker_profile_paths[i];
            let worker_model = CostModel::from_fixed_circuit_csv(p, g)?;
            anyhow::ensure!(
                worker_model.circuit_id == cm.circuit_id,
                "worker profile {p} uses a different group circuit"
            );
            Some(worker_model.reference_profile(p.clone()))
        };
        w.bandwidth_mbps = worker_bandwidths[i];
        w.latency_ms = worker_latencies[i];
        planner_workers.push(w);
    }
    let raw_objective = Objective::default();
    let reference_plan = plan_max_fit(k, &planner_workers, &cm, g);
    let reference_cost = evaluate(&reference_plan, &planner_workers, &cm, &raw_objective);
    let obj = if reference_cost.feasible {
        raw_objective.normalised_by(&reference_cost)
    } else {
        raw_objective
    };
    let plan = match scheduler.as_str() {
        "maxfit" => plan_max_fit(k, &planner_workers, &cm, g),
        "equal" => plan_equal_size(k, &planner_workers, &cm, g),
        "onepertx" => plan_one_per_group(k, &planner_workers, &cm),
        "eft" => plan_earliest_finish(k, &planner_workers, &cm, g),
        "minmin" => plan_min_min(k, &planner_workers, &cm, g),
        "maxmin" => plan_max_min(k, &planner_workers, &cm, g),
        "heft" => plan_heft(k, &planner_workers, &cm, g),
        "lst" => plan_lst_capacity(k, &planner_workers, &cm, g),
        "marginal" => plan_greedy_marginal(k, &planner_workers, &cm, &obj, g),
        "resource" => plan_resource_aware(
            k,
            &planner_workers,
            &cm,
            &obj,
            g,
            &HeuristicConfig::default(),
        ),
        other => anyhow::bail!("unsupported scheduler {other}"),
    };
    validate_plan(&plan, &planner_workers, &cm)?;
    anyhow::ensure!(
        plan.groups.len() as u64 <= MAX_BLOCK_GROUPS,
        "planned group count exceeds the bounded block circuit"
    );
    let predicted = evaluate(&plan, &planner_workers, &cm, &obj);
    eprintln!("plan: {} groups -> {}", plan.groups.len(), predicted);

    let mut tasks: Vec<TaskSpec> = Vec::new();
    let mut cursor = 0usize;
    for (i, &(size, wid)) in plan.groups.iter().enumerate() {
        let end = (cursor + size).min(all_txs.len());
        let txs = all_txs[cursor..end].to_vec();
        let sigs = all_sigs[cursor..end].to_vec();
        let digest = group_digest(&txs, g);
        tasks.push(TaskSpec {
            id: i,
            group_index: i as u64,
            size: end - cursor,
            txs,
            sigs,
            planned_worker: wid,
            digest,
        });
        cursor = end;
    }
    anyhow::ensure!(
        cursor == all_txs.len(),
        "plan must cover every transaction exactly once"
    );

    let mut acc = zero_hash();
    for t in &tasks {
        acc = fold_acc(acc, t.digest);
    }
    let root = acc;
    let mut early_circuits = if e2e_csv.is_some() {
        let gc = build_group_circuit(g);
        let bc = build_block_circuit_with_fan_in(&gc, block_fan_in);
        Some((gc, bc))
    } else {
        None
    };
    let chain_run = if let Some((gc, bc)) = &early_circuits {
        Some(pcb_recursive::e2e::ChainRun::new(
            bc, gc, chain_in.as_deref().map(std::path::Path::new), chain_height,
        )?)
    } else {
        None
    };
    let genesis = HashOut { elements: [F::from_canonical_u64(0xACE0); 4] };
    let bid = block_id(
        chain_run.as_ref().map_or(1, |run| run.height),
        chain_run.as_ref().map_or(genesis, |run| run.previous_tip), root,
    );

    let listener = TcpListener::bind(("127.0.0.1", port as u16))?;
    let exe = std::env::current_exe()?;
    let worker_exe = exe.with_file_name(if cfg!(windows) {
        "pcb_worker.exe"
    } else {
        "pcb_worker"
    });
    let cores_each = argu(&args, "--cores-per-worker", 1);
    anyhow::ensure!(
        (1..=64).contains(&cores_each),
        "cores per worker must be in 1..=64"
    );
    let spawn = argu(&args, "--spawn-workers", nworkers).min(nworkers);
    if spawn < nworkers {
        eprintln!(
            "waiting for {} external worker(s) with ids {}..{} to connect on port {port}",
            nworkers - spawn,
            spawn,
            nworkers - 1
        );
    }
    #[cfg(unix)]
    let worker_cpus = if worker_affinity_policy == "logical" {
        logical_cpu_ids()
    } else {
        physical_cpu_ids()
    };
    #[cfg(unix)]
    anyhow::ensure!(
        spawn * cores_each <= worker_cpus.len(),
        "requested {} pinned cores for {} workers, found {} CPUs under the {} policy",
        spawn * cores_each,
        spawn,
        worker_cpus.len(),
        worker_affinity_policy
    );
    let mut children: Vec<Child> = Vec::new();
    for i in 0..spawn {
        let f = if i == 0 { fault.clone() } else { "none".into() };
        let want = cores_each;
        #[cfg(unix)]
        let mut cmd = {
            let cores: Vec<String> = (0..want)
                .map(|c| worker_cpus[i * cores_each + c].to_string())
                .collect();
            let mut c = Command::new("taskset");
            c.arg("-c").arg(cores.join(",")).arg(&worker_exe);
            c
        };
        #[cfg(not(unix))]
        let mut cmd = Command::new(&worker_exe);
        let c = cmd
            .arg(format!("127.0.0.1:{port}"))
            .arg(i.to_string())
            .arg(g.to_string())
            .arg(mems[i].to_string())
            .arg(f)
            .arg(want.to_string())
            .arg(i.to_string())
            .spawn()?;
        children.push(c);
    }

    let t_start = Instant::now();
    let (tx, rx) = mpsc::channel::<(usize, Option<TaskResult>)>();
    let mut writers: HashMap<usize, TcpStream> = HashMap::new();
    let mut hellos: HashMap<usize, Hello> = HashMap::new();
    for _ in 0..nworkers {
        let (mut s, _) = listener.accept()?;
        s.set_nodelay(true)?;
        let (tag_b, payload) = read_frame(&mut s)?;
        anyhow::ensure!(tag_b == TAG_HELLO, "expected hello");
        let h = Hello::decode(&payload)?;
        let wid = h.worker_id;
        anyhow::ensure!(
            wid < nworkers,
            "worker id {wid} is outside the configured fleet"
        );
        anyhow::ensure!(!hellos.contains_key(&wid), "duplicate worker id {wid}");
        let mem_tolerance = 1e-6 * mems[wid].abs().max(1.0);
        anyhow::ensure!(
            (h.mem_mb - mems[wid]).abs() <= mem_tolerance,
            "worker {wid} announced a memory budget different from the planned value"
        );
        anyhow::ensure!(
            h.cores == cores_each,
            "worker {wid} announced a core allocation different from the planned value"
        );
        anyhow::ensure!(
            h.affinity_mask != 0,
            "worker {wid} reported an empty CPU affinity"
        );
        hellos.insert(wid, h);
        let mut reader = s.try_clone()?;
        writers.insert(wid, s);
        let txc = tx.clone();
        std::thread::spawn(move || loop {
            match read_frame(&mut reader) {
                Ok((TAG_RESULT, p)) => match TaskResult::decode(&p) {
                    Ok(result) => {
                        let _ = txc.send((wid, Some(result)));
                    }
                    Err(_) => {
                        let _ = txc.send((wid, None));
                        break;
                    }
                },
                Ok(_) => {}
                Err(_) => {
                    let _ = txc.send((wid, None));
                    break;
                }
            }
        });
    }
    let setup_ms = t_start.elapsed().as_secs_f64() * 1000.0;
    let max_build_ms = hellos.values().map(|h| h.build_ms).fold(0.0f64, f64::max);
    eprintln!(
        "{} workers registered in {:.0} ms (max circuit build {:.0} ms)",
        nworkers, setup_ms, max_build_ms
    );

    let (gc, bc) = early_circuits.take().unwrap_or_else(|| {
        let gc = build_group_circuit(g);
        let bc = build_block_circuit_with_fan_in(&gc, block_fan_in);
        (gc, bc)
    });
    debug_assert_eq!(gc.circuit_id, deployed_circuit_id);

    #[derive(Clone)]
    struct Rec {
        task: usize,
        attempt: usize,
        worker: usize,
        size: usize,
        prove_ms: f64,
        transfer_ms: f64,
        verify_ms: f64,
        #[allow(dead_code)]
        bytes_out: usize,
        bytes_in: usize,
        peak_mb: f64,
        predicted_ms: f64,
        prediction_error_pct: f64,
        profile_updated: bool,
        status: String,
        t_end_ms: f64,
    }
    let mut recs: Vec<Rec> = Vec::new();

    let mut queue: Vec<usize> = (0..tasks.len()).rev().collect();
    let mut done: HashMap<usize, Proof> = HashMap::new();
    let mut inflight: HashMap<usize, (usize, Instant, usize, f64)> = HashMap::new();
    let mut attempts: Vec<usize> = vec![0; tasks.len()];
    let mut alive: Vec<bool> = vec![true; nworkers];
    let mut busy: Vec<bool> = vec![false; nworkers];
    let mut bytes_out_total = 0usize;
    let mut bytes_in_total = 0usize;
    let mut retries = 0usize;
    let mut duplicates = 0usize;
    let mut wasted_ms = 0.0f64;
    let mut first_failure_at: Option<f64> = None;
    let mut recovery_task: Option<usize> = None;
    let mut recovered_at: Option<f64> = None;
    let mut worker_busy_ms = vec![0.0f64; nworkers];
    let mut coordinator_ms = 0.0f64;
    let mut profile_updates = 0usize;

    let t_dispatch = Instant::now();
    while done.len() < tasks.len() {
        let mut progress = false;
        let mut i = queue.len();
        while i > 0 {
            i -= 1;
            let tid = queue[i];
            if let Some(w) = pick_worker(
                tasks[tid].size,
                tasks[tid].planned_worker,
                &alive,
                &busy,
                &planner_workers,
                &cm,
            ) {
                queue.remove(i);
                let t = &tasks[tid];
                let msg = Task {
                    task_id: t.id,
                    attempt: attempts[tid],
                    block_id: bid,
                    group_index: t.group_index,
                    circuit_budget: g,
                    circuit_id: gc.circuit_id,
                    predicted_ms: cm.prove_ms_on(t.size, &planner_workers[w]),
                    txs: t.txs.clone(),
                    sigs: t.sigs.clone(),
                };
                let payload = msg.encode();
                let frame_bytes = payload.len() + 5;
                let shape = latency_ms
                    + if bandwidth.is_finite() {
                        frame_bytes as f64 * 8.0 / (bandwidth * 1000.0)
                    } else {
                        0.0
                    };
                if shape > 0.0 {
                    std::thread::sleep(Duration::from_micros((shape * 1000.0) as u64));
                }
                let c0 = Instant::now();
                match write_frame(writers.get_mut(&w).unwrap(), TAG_TASK, &payload) {
                    Ok(n) => {
                        bytes_out_total += n;
                        busy[w] = true;
                        let predicted_ms = cm.prove_ms_on(t.size, &planner_workers[w]);
                        inflight.insert(w, (tid, Instant::now(), attempts[tid], predicted_ms));
                        progress = true;
                    }
                    Err(_) => {
                        alive[w] = false;
                        queue.push(tid);
                    }
                }
                coordinator_ms += c0.elapsed().as_secs_f64() * 1000.0;
            }
        }
        let _ = progress;

        if inflight.is_empty() && queue.is_empty() {
            break;
        }
        if inflight.is_empty()
            && !queue.is_empty()
            && !queue.iter().any(|&tid| {
                pick_worker(
                    tasks[tid].size,
                    tasks[tid].planned_worker,
                    &alive,
                    &busy,
                    &planner_workers,
                    &cm,
                )
                .is_some()
            })
        {
            anyhow::bail!(
                "no live worker can hold the remaining {} tasks",
                queue.len()
            );
        }
        if inflight.is_empty() && !alive.iter().any(|&a| a) {
            anyhow::bail!("every worker failed; block cannot be produced");
        }

        let wait = Duration::from_millis(250);
        match rx.recv_timeout(wait) {
            Ok((wid, Some(res))) => {
                let tid = res.task_id;
                let incoming_payload_bytes = res.encoded_len();
                let incoming_frame_bytes = incoming_payload_bytes + 5;
                bytes_in_total += incoming_frame_bytes;
                let receive_shape = latency_ms
                    + if bandwidth.is_finite() {
                        incoming_frame_bytes as f64 * 8.0 / (bandwidth * 1000.0)
                    } else {
                        0.0
                    };
                if receive_shape > 0.0 {
                    std::thread::sleep(Duration::from_micros((receive_shape * 1000.0) as u64));
                }
                let expected = inflight
                    .get(&wid)
                    .map(|(task, _, attempt, _)| (*task, *attempt));
                let kind = if res.worker_id != wid || tid >= tasks.len() {
                    IncomingResultKind::Unexpected
                } else {
                    classify_incoming_result(done.contains_key(&tid), expected, tid, res.attempt)
                };

                match kind {
                    IncomingResultKind::Duplicate => {
                        duplicates += 1;
                        let predicted_ms = cm.prove_ms_on(tasks[tid].size, &planner_workers[wid]);
                        recs.push(Rec {
                            task: tid,
                            attempt: res.attempt,
                            worker: wid,
                            size: tasks[tid].size,
                            prove_ms: res.prove_ms,
                            transfer_ms: 0.0,
                            verify_ms: 0.0,
                            bytes_out: 0,
                            bytes_in: incoming_frame_bytes,
                            peak_mb: res.peak_mb,
                            predicted_ms,
                            prediction_error_pct: 0.0,
                            profile_updated: false,
                            status: "duplicate-ignored".into(),
                            t_end_ms: t_dispatch.elapsed().as_secs_f64() * 1000.0,
                        });
                        continue;
                    }
                    IncomingResultKind::Unexpected => {
                        let entry = inflight.remove(&wid);
                        let (record_task, size, predicted_ms, status) = match entry {
                            Some((expected_tid, since, _, predicted_ms)) => {
                                busy[wid] = false;
                                alive[wid] = false;
                                wasted_ms += since.elapsed().as_secs_f64() * 1000.0;
                                retries += 1;
                                attempts[expected_tid] += 1;
                                queue.push(expected_tid);
                                note_first_failure(
                                    &mut first_failure_at,
                                    &mut recovery_task,
                                    expected_tid,
                                    t_dispatch.elapsed().as_secs_f64() * 1000.0,
                                );
                                writers.remove(&wid);
                                (
                                    expected_tid,
                                    tasks[expected_tid].size,
                                    predicted_ms,
                                    "protocol-rejected",
                                )
                            }
                            None => {
                                let record_task = tid.min(tasks.len().saturating_sub(1));
                                let size = tasks.get(record_task).map_or(0, |task| task.size);
                                let predicted_ms = tasks.get(record_task).map_or(0.0, |task| {
                                    cm.prove_ms_on(task.size, &planner_workers[wid])
                                });
                                (
                                    record_task,
                                    size,
                                    predicted_ms,
                                    "quarantined-output-ignored",
                                )
                            }
                        };
                        recs.push(Rec {
                            task: record_task,
                            attempt: res.attempt,
                            worker: wid,
                            size,
                            prove_ms: res.prove_ms,
                            transfer_ms: 0.0,
                            verify_ms: 0.0,
                            bytes_out: 0,
                            bytes_in: incoming_frame_bytes,
                            peak_mb: res.peak_mb,
                            predicted_ms,
                            prediction_error_pct: 0.0,
                            profile_updated: false,
                            status: status.into(),
                            t_end_ms: t_dispatch.elapsed().as_secs_f64() * 1000.0,
                        });
                        continue;
                    }
                    IncomingResultKind::Expected => {}
                }

                busy[wid] = false;
                let (_, since, _, predicted_ms) = inflight
                    .remove(&wid)
                    .expect("a classified expected result has an inflight assignment");
                let elapsed = since.elapsed().as_secs_f64() * 1000.0;
                let prediction_error_pct = if res.prove_ms > 0.0 {
                    100.0 * (res.prove_ms - predicted_ms).abs() / res.prove_ms
                } else {
                    0.0
                };

                let tv = Instant::now();
                let ok = match Proof::from_bytes(res.proof.clone(), &gc.data.common) {
                    Ok(p) => {
                        let pis = &p.public_inputs;
                        let idx_ok =
                            pis[GPI_GROUP_INDEX] == F::from_canonical_u64(tasks[tid].group_index);
                        let bid_ok = pis[GPI_BLOCK_ID..GPI_BLOCK_ID + 4] == bid.elements;
                        let cid_ok =
                            pis[GPI_CIRCUIT_ID..GPI_CIRCUIT_ID + 4] == gc.circuit_id.elements;
                        let budget_ok = pis[GPI_GROUP_BUDGET] == F::from_canonical_u64(g as u64);
                        let dg_ok = pis[GPI_GROUP_DIGEST..GPI_GROUP_DIGEST + 4]
                            == tasks[tid].digest.elements;
                        let n_ok =
                            pis[GPI_TX_COUNT] == F::from_canonical_u64(tasks[tid].size as u64);
                        if idx_ok
                            && bid_ok
                            && cid_ok
                            && budget_ok
                            && dg_ok
                            && n_ok
                            && gc.data.verify(p.clone()).is_ok()
                        {
                            Some(p)
                        } else {
                            None
                        }
                    }
                    Err(_) => None,
                };
                let verify_ms = tv.elapsed().as_secs_f64() * 1000.0;
                coordinator_ms += verify_ms;

                match ok {
                    Some(p) => {
                        worker_busy_ms[wid] += res.prove_ms;
                        let profile_updated = planner_workers[wid]
                            .profile
                            .as_mut()
                            .map(|profile| {
                                profile.observe(
                                    tasks[tid].size,
                                    res.prove_ms,
                                    recalibrate_threshold,
                                )
                            })
                            .unwrap_or(false);
                        profile_updates += usize::from(profile_updated);
                        done.insert(tid, p);
                        recs.push(Rec {
                            task: tid,
                            attempt: res.attempt,
                            worker: wid,
                            size: tasks[tid].size,
                            prove_ms: res.prove_ms,
                            transfer_ms: (elapsed - res.prove_ms).max(0.0),
                            verify_ms,
                            bytes_out: 0,
                            bytes_in: incoming_frame_bytes,
                            peak_mb: res.peak_mb,
                            predicted_ms,
                            prediction_error_pct,
                            profile_updated,
                            status: "ok".into(),
                            t_end_ms: t_dispatch.elapsed().as_secs_f64() * 1000.0,
                        });
                        note_replacement(
                            recovery_task,
                            &mut recovered_at,
                            tid,
                            t_dispatch.elapsed().as_secs_f64() * 1000.0,
                        );
                    }
                    None => {
                        wasted_ms += res.prove_ms;
                        retries += 1;
                        attempts[tid] += 1;
                        alive[wid] = false;
                        writers.remove(&wid);
                        note_first_failure(
                            &mut first_failure_at,
                            &mut recovery_task,
                            tid,
                            t_dispatch.elapsed().as_secs_f64() * 1000.0,
                        );
                        queue.push(tid);
                        recs.push(Rec {
                            task: tid,
                            attempt: res.attempt,
                            worker: wid,
                            size: tasks[tid].size,
                            prove_ms: res.prove_ms,
                            transfer_ms: (elapsed - res.prove_ms).max(0.0),
                            verify_ms,
                            bytes_out: 0,
                            bytes_in: incoming_frame_bytes,
                            peak_mb: res.peak_mb,
                            predicted_ms,
                            prediction_error_pct,
                            profile_updated: false,
                            status: "invalid-rejected".into(),
                            t_end_ms: t_dispatch.elapsed().as_secs_f64() * 1000.0,
                        });
                    }
                }
            }
            Ok((wid, None)) => {
                alive[wid] = false;
                busy[wid] = false;
                if let Some((tid, since, att, predicted_ms)) = inflight.remove(&wid) {
                    wasted_ms += since.elapsed().as_secs_f64() * 1000.0;
                    retries += 1;
                    attempts[tid] += 1;
                    queue.push(tid);
                    note_first_failure(
                        &mut first_failure_at,
                        &mut recovery_task,
                        tid,
                        t_dispatch.elapsed().as_secs_f64() * 1000.0,
                    );
                    recs.push(Rec {
                        task: tid,
                        attempt: att,
                        worker: wid,
                        size: tasks[tid].size,
                        prove_ms: 0.0,
                        transfer_ms: 0.0,
                        verify_ms: 0.0,
                        bytes_out: 0,
                        bytes_in: 0,
                        peak_mb: 0.0,
                        predicted_ms,
                        prediction_error_pct: 0.0,
                        profile_updated: false,
                        status: "crash-reassigned".into(),
                        t_end_ms: t_dispatch.elapsed().as_secs_f64() * 1000.0,
                    });
                }
            }
            Err(_) => {
                let expired: Vec<usize> = inflight
                    .iter()
                    .filter(|(_, (_, s, _, predicted))| {
                        let deadline = timeout_ms.max(*predicted * timeout_factor.max(1.0));
                        s.elapsed().as_secs_f64() * 1000.0 > deadline
                    })
                    .map(|(w, _)| *w)
                    .collect();
                for w in expired {
                    if let Some((tid, since, att, predicted_ms)) = inflight.remove(&w) {
                        alive[w] = false;
                        busy[w] = false;
                        wasted_ms += since.elapsed().as_secs_f64() * 1000.0;
                        retries += 1;
                        attempts[tid] += 1;
                        queue.push(tid);
                        note_first_failure(
                            &mut first_failure_at,
                            &mut recovery_task,
                            tid,
                            t_dispatch.elapsed().as_secs_f64() * 1000.0,
                        );
                        recs.push(Rec {
                            task: tid,
                            attempt: att,
                            worker: w,
                            size: tasks[tid].size,
                            prove_ms: 0.0,
                            transfer_ms: 0.0,
                            verify_ms: 0.0,
                            bytes_out: 0,
                            bytes_in: 0,
                            peak_mb: 0.0,
                            predicted_ms,
                            prediction_error_pct: 0.0,
                            profile_updated: false,
                            status: "timeout-reassigned".into(),
                            t_end_ms: t_dispatch.elapsed().as_secs_f64() * 1000.0,
                        });
                    }
                }
                if !alive.iter().any(|&a| a) && !queue.is_empty() {
                    anyhow::bail!(
                        "no live worker can take the remaining {} tasks",
                        queue.len()
                    );
                }
            }
        }
    }
    if duplicate_grace_ms > 0.0 {
        let grace = Instant::now();
        while grace.elapsed().as_secs_f64() * 1000.0 < duplicate_grace_ms {
            let left = duplicate_grace_ms - grace.elapsed().as_secs_f64() * 1000.0;
            match rx.recv_timeout(Duration::from_millis(left.clamp(1.0, 250.0) as u64)) {
                Ok((wid, Some(res))) if done.contains_key(&res.task_id) => {
                    let incoming_payload_bytes = res.encoded_len();
                    let incoming_frame_bytes = incoming_payload_bytes + 5;
                    bytes_in_total += incoming_frame_bytes;
                    let receive_shape = latency_ms
                        + if bandwidth.is_finite() {
                            incoming_frame_bytes as f64 * 8.0 / (bandwidth * 1000.0)
                        } else {
                            0.0
                        };
                    if receive_shape > 0.0 {
                        std::thread::sleep(Duration::from_micros((receive_shape * 1000.0) as u64));
                    }
                    duplicates += 1;
                    recs.push(Rec {
                        task: res.task_id,
                        attempt: res.attempt,
                        worker: wid,
                        size: tasks[res.task_id].size,
                        prove_ms: res.prove_ms,
                        transfer_ms: 0.0,
                        verify_ms: 0.0,
                        bytes_out: 0,
                        bytes_in: incoming_frame_bytes,
                        peak_mb: res.peak_mb,
                        predicted_ms: cm
                            .prove_ms_on(tasks[res.task_id].size, &planner_workers[wid]),
                        prediction_error_pct: 0.0,
                        profile_updated: false,
                        status: "late-duplicate-ignored".into(),
                        t_end_ms: t_dispatch.elapsed().as_secs_f64() * 1000.0,
                    });
                }
                Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
    }
    let prove_phase_ms = t_dispatch.elapsed().as_secs_f64() * 1000.0;
    anyhow::ensure!(
        first_failure_at.is_none() || recovered_at.is_some(),
        "the first failed task did not produce an accepted replacement"
    );

    anyhow::ensure!(done.len() == tasks.len(), "not every group was proven");
    let ordered_proofs: Vec<Proof> = tasks
        .iter()
        .map(|task| done.get(&task.id).expect("group proof present").clone())
        .collect();
    let aggregation_depth = ordered_proofs.len().div_ceil(block_fan_in);
    let agg_cpu_start = process_cpu_ms();
    let t_agg = Instant::now();
    let mut block_proof = None;
    for proofs in ordered_proofs.chunks(block_fan_in) {
        block_proof = Some(bc.step_batch(bid, proofs, block_proof.as_ref())?);
    }
    let block_proof = block_proof.unwrap();
    let agg_ms = t_agg.elapsed().as_secs_f64() * 1000.0;
    let agg_cpu_ms = match (agg_cpu_start, process_cpu_ms()) {
        (Some(start), Some(end)) => (end - start).max(0.0),
        _ => f64::NAN,
    };
    let t_block_verify = Instant::now();
    bc.verify_block(&block_proof, bid, root, tasks.len() as u64, k as u64)?;
    let block_verify_ms = t_block_verify.elapsed().as_secs_f64() * 1000.0;
    let total_ms = t_dispatch.elapsed().as_secs_f64() * 1000.0;

    if let (Some(run), Some(path), Some(destination)) = (&chain_run, &e2e_csv, &chain_out) {
        let measured = run.finish(
            &block_proof, bid, root, tasks.len() as u64, k as u64, std::path::Path::new(destination),
        )?;
        let cold_ms = cold_start.elapsed().as_secs_f64() * 1000.0;
        let hash_text = |hash: HashOut<F>| hash.elements.iter()
            .map(|x| format!("{:016x}", x.to_canonical_u64())).collect::<String>();
        let header = "tag,rep,seed,height,k,g,workers,local_workers,scheduler,queries,input_digest,block_root,chain_commitment,chain_tip,block_ms,chain_prove_ms,chain_verify_ms,chain_persist_ms,online_ms,cold_ms,chain_proof_bytes,verified";
        let line = format!(
            "{tag},{repetition},{seed},{},{k},{g},{nworkers},{spawn},{scheduler},{},{},{},{},{},{total_ms:.3},{:.3},{:.3},{:.3},{:.3},{cold_ms:.3},{},true",
            run.height, std::env::var("PCB_FRI_QUERIES").unwrap_or_else(|_| "28".into()),
            hash_text(group_digest(&all_txs, k)), hash_text(root),
            hash_text(measured.commitment), hash_text(measured.tip),
            measured.prove_ms, measured.verify_ms, measured.persist_ms,
            total_ms + measured.prove_ms + measured.verify_ms, measured.proof_bytes,
        );
        let new = !std::path::Path::new(path).exists();
        let mut file = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
        if new { writeln!(file, "{header}")?; }
        writeln!(file, "{line}")?;
    }

    for s in writers.values_mut() {
        let _ = write_frame(s, TAG_SHUTDOWN, &[]);
    }
    for c in &mut children {
        let _ = c.kill();
        let _ = c.wait();
    }

    let worker_peaks: Vec<f64> = (0..nworkers)
        .map(|i| {
            recs.iter()
                .filter(|r| r.worker == i)
                .map(|r| r.peak_mb)
                .fold(0.0f64, f64::max)
        })
        .collect();
    let cluster_mb: f64 = worker_peaks.iter().sum();
    let busy_max = worker_busy_ms.iter().cloned().fold(0.0f64, f64::max);
    let busy_mean = worker_busy_ms.iter().sum::<f64>() / nworkers as f64;
    let imbalance = if busy_mean > 0.0 {
        busy_max / busy_mean
    } else {
        1.0
    };
    let idle_ms: f64 = worker_busy_ms
        .iter()
        .map(|b| (prove_phase_ms - b).max(0.0))
        .sum();
    let cpu_ms: f64 = worker_busy_ms.iter().sum();
    let stored: usize = tasks.iter().map(|t| done[&t.id].to_bytes().len()).sum();
    let prediction_errors: Vec<f64> = recs
        .iter()
        .filter(|r| r.status == "ok" && r.prove_ms > 0.0)
        .map(|r| r.prediction_error_pct)
        .collect();
    let prediction_mape_pct = if prediction_errors.is_empty() {
        0.0
    } else {
        prediction_errors.iter().sum::<f64>() / prediction_errors.len() as f64
    };
    let recovery_ms = match (first_failure_at, recovered_at) {
        (Some(detected), Some(recovered)) => Some((recovered - detected).max(0.0)),
        _ => None,
    };
    let run_end_unix_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();

    if let Some(path) = &tasks_csv {
        let new = !std::path::Path::new(path).exists();
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        if new {
            writeln!(f, "tag,rep,run_start_unix_ms,scheduler,k,g,workers,task,attempt,worker,affinity_mask,size,predicted_ms,prove_ms,prediction_error_pct,profile_updated,transfer_ms,verify_ms,bytes_in,peak_mb,status,t_end_ms")?;
        }
        for r in &recs {
            writeln!(
                f,
                "{tag},{repetition},{run_start_unix_ms},{scheduler},{k},{g},{nworkers},{},{},{},{:016x},{},{:.1},{:.1},{:.2},{},{:.1},{:.3},{},{:.0},{},{:.1}",
                r.task,
                r.attempt,
                r.worker,
                hellos[&r.worker].affinity_mask,
                r.size,
                r.predicted_ms,
                r.prove_ms,
                r.prediction_error_pct,
                r.profile_updated,
                r.transfer_ms,
                r.verify_ms,
                r.bytes_in,
                r.peak_mb,
                r.status,
                r.t_end_ms
            )?;
        }
    }

    let worker_affinity_masks = (0..nworkers)
        .map(|worker| format!("{worker}={:016x}", hellos[&worker].affinity_mask))
        .collect::<Vec<_>>()
        .join("|");
    let header = "tag,rep,run_start_unix_ms,run_end_unix_ms,node_label,local_workers,remote_workers,scheduler,k,g,workers,worker_affinity_policy,worker_affinity_masks,fault,latency_ms,bandwidth_mbps,groups,prove_phase_ms,agg_ms,total_ms,throughput_tps,cpu_ms,idle_ms,imbalance,coordinator_ms,setup_ms,max_build_ms,bytes_out,bytes_in,retries,reassignments,duplicates,wasted_ms,extra_cpu_s,recovery_origin,recovery_ms,lost_work_pct,max_worker_peak_mb,cluster_peak_mb,stored_bytes,block_proof_bytes,coord_peak_mb,predicted_makespan_ms,prediction_mape_pct,profile_updates,final_proof_valid,block_fan_in,aggregation_depth,agg_cpu_ms,block_verify_ms";
    let line = vec![
        tag.clone(),
        repetition.to_string(),
        run_start_unix_ms.to_string(),
        run_end_unix_ms.to_string(),
        node_label.clone(),
        spawn.to_string(),
        (nworkers - spawn).to_string(),
        scheduler.clone(),
        k.to_string(),
        g.to_string(),
        nworkers.to_string(),
        worker_affinity_policy,
        worker_affinity_masks,
        fault.clone(),
        latency_ms.to_string(),
        if bandwidth.is_finite() {
            bandwidth.to_string()
        } else {
            "inf".into()
        },
        tasks.len().to_string(),
        format!("{prove_phase_ms:.1}"),
        format!("{agg_ms:.1}"),
        format!("{total_ms:.1}"),
        format!("{:.3}", k as f64 / (total_ms / 1000.0)),
        format!("{cpu_ms:.1}"),
        format!("{idle_ms:.1}"),
        format!("{imbalance:.3}"),
        format!("{coordinator_ms:.1}"),
        format!("{setup_ms:.1}"),
        format!("{max_build_ms:.1}"),
        bytes_out_total.to_string(),
        bytes_in_total.to_string(),
        retries.to_string(),
        retries.to_string(),
        duplicates.to_string(),
        format!("{wasted_ms:.1}"),
        format!("{:.3}", wasted_ms / 1000.0),
        if first_failure_at.is_some() {
            "first-fault-detection".into()
        } else {
            "NA".into()
        },
        recovery_ms
            .map(|v| format!("{v:.1}"))
            .unwrap_or_else(|| "NA".into()),
        format!(
            "{:.2}",
            if cpu_ms + wasted_ms > 0.0 {
                100.0 * wasted_ms / (cpu_ms + wasted_ms)
            } else {
                0.0
            }
        ),
        format!("{:.0}", worker_peaks.iter().cloned().fold(0.0f64, f64::max)),
        format!("{cluster_mb:.0}"),
        stored.to_string(),
        block_proof.to_bytes().len().to_string(),
        format!("{:.0}", peak_working_set_mb()),
        format!("{:.1}", predicted.makespan_ms),
        format!("{prediction_mape_pct:.2}"),
        profile_updates.to_string(),
        "true".into(),
        block_fan_in.to_string(),
        aggregation_depth.to_string(),
        if agg_cpu_ms.is_finite() {
            format!("{agg_cpu_ms:.1}")
        } else {
            "NR".into()
        },
        format!("{block_verify_ms:.3}"),
    ]
    .join(",");
    println!("{header}");
    println!("{line}");
    if let Some(path) = &summary_csv {
        let new = !std::path::Path::new(path).exists();
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        if new {
            writeln!(f, "{header}")?;
        }
        writeln!(f, "{line}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        classify_incoming_result, note_first_failure, note_replacement, physical_first_cpu_order,
        pick_worker, IncomingResultKind,
    };
    use pcb_recursive::sched::{CostModel, Worker};

    fn dispatch_model() -> CostModel {
        CostModel {
            circuit_budget: 4,
            circuit_id: "dispatch-test".into(),
            sizes: vec![1, 2, 3, 4],
            prove_ms: vec![1.0, 2.0, 3.0, 4.0],
            peak_mb: vec![64.0; 4],
            proof_bytes: vec![1024.0; 4],
            verify_ms: vec![1.0; 4],
            agg_step_ms: 1.0,
            agg_peak_mb: 64.0,
            witness_bytes_per_tx: 64.0,
        }
    }

    #[test]
    fn completed_duplicate_does_not_consume_a_new_inflight_assignment() {
        let current_assignment = Some((7, 0));
        assert_eq!(
            classify_incoming_result(true, current_assignment, 3, 0),
            IncomingResultKind::Duplicate
        );
    }

    #[test]
    fn result_must_match_both_task_and_attempt() {
        assert_eq!(
            classify_incoming_result(false, Some((7, 2)), 7, 2),
            IncomingResultKind::Expected
        );
        assert_eq!(
            classify_incoming_result(false, Some((7, 2)), 6, 2),
            IncomingResultKind::Unexpected
        );
        assert_eq!(
            classify_incoming_result(false, Some((7, 2)), 7, 1),
            IncomingResultKind::Unexpected
        );
        assert_eq!(
            classify_incoming_result(false, None, 7, 2),
            IncomingResultKind::Unexpected
        );
    }

    #[test]
    fn logical_cpu_order_uses_each_physical_core_before_smt_siblings() {
        let cores = vec![vec![0, 12], vec![1, 13], vec![2, 14]];
        assert_eq!(physical_first_cpu_order(&cores), vec![0, 1, 2, 12, 13, 14]);
    }

    #[test]
    fn recovery_ends_when_the_first_failed_task_is_replaced() {
        let mut detected_at = None;
        let mut recovery_task = None;
        let mut recovered_at = None;

        note_first_failure(&mut detected_at, &mut recovery_task, 4, 10.0);
        note_first_failure(&mut detected_at, &mut recovery_task, 7, 12.0);
        assert_eq!(detected_at, Some(10.0));
        assert_eq!(recovery_task, Some(4));
        assert!(!note_replacement(recovery_task, &mut recovered_at, 7, 30.0));
        assert!(note_replacement(recovery_task, &mut recovered_at, 4, 40.0));
        assert_eq!(recovered_at, Some(40.0));
    }

    #[test]
    fn queued_group_waits_for_its_live_planned_worker() {
        let cm = dispatch_model();
        let workers = vec![Worker::homogeneous(0, 1024.0), Worker::homogeneous(1, 1024.0)];
        let alive = vec![true, true];
        let busy = vec![true, false];

        assert_eq!(pick_worker(4, 0, &alive, &busy, &workers, &cm), None);
    }

    #[test]
    fn failed_planned_worker_triggers_feasible_fallback() {
        let cm = dispatch_model();
        let workers = vec![Worker::homogeneous(0, 1024.0), Worker::homogeneous(1, 1024.0)];
        let alive = vec![false, true];
        let busy = vec![false, false];

        assert_eq!(pick_worker(4, 0, &alive, &busy, &workers, &cm), Some(1));
    }
}
