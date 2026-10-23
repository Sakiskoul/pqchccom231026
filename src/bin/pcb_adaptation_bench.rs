use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use anyhow::{ensure, Result};
use pcb_recursive::net::*;
use pcb_recursive::pcc::*;
use pcb_recursive::sched::*;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::plonk::proof::ProofWithPublicInputs;

const PACE: u8 = 6;

fn milliseconds(t: Instant) -> f64 { t.elapsed().as_secs_f64() * 1000.0 }

fn worker(addr: &str, id: usize, g: usize) -> Result<()> {
    let gc = build_group_circuit(g);
    let mut socket = TcpStream::connect(addr)?;
    socket.set_nodelay(true)?;
    write_frame(&mut socket, TAG_READY, &(id as u64).to_le_bytes())?;
    let mut factor = 1.0;
    loop {
        let (tag, payload) = read_frame(&mut socket)?;
        match tag {
            TAG_SHUTDOWN => return Ok(()),
            PACE => {
                ensure!(payload.len() == 8, "invalid pacing payload");
                factor = f64::from_le_bytes(payload.try_into().unwrap());
                ensure!(factor.is_finite() && (1.0..=8.0).contains(&factor), "invalid pacing factor");
            }
            TAG_TASK => {
                let task = Task::decode(&payload)?;
                ensure!(task.circuit_budget == g && task.circuit_id == gc.circuit_id, "wrong circuit");
                let start = Instant::now();
                let proof = prove_group(&gc, task.block_id, task.group_index, &task.txs, &task.sigs)?;
                let compute_ms = milliseconds(start);
                std::thread::sleep(Duration::from_secs_f64(compute_ms * (factor - 1.0) / 1000.0));
                let result = TaskResult { task_id: task.task_id, attempt: task.attempt, worker_id: id,
                    prove_ms: milliseconds(start), peak_mb: pcb_recursive::mem::peak_working_set_mb(),
                    proof: proof.to_bytes() };
                write_frame(&mut socket, TAG_RESULT, &result.encode())?;
            }
            _ => anyhow::bail!("unknown benchmark command"),
        }
    }
}

struct Children(Vec<Child>);
impl Drop for Children {
    fn drop(&mut self) {
        for child in &mut self.0 { let _ = child.kill(); let _ = child.wait(); }
    }
}

fn execute(sockets: &mut [TcpStream], tasks: &[Vec<Task>], gc: &GroupCircuit)
    -> Result<Vec<(Task, TaskResult)>> {
    std::thread::scope(|scope| {
        let handles: Vec<_> = sockets.iter_mut().zip(tasks).enumerate().map(|(wid, (socket, batch))| {
            scope.spawn(move || -> Result<Vec<(Task, TaskResult)>> {
                let mut results = Vec::new();
                for task in batch {
                    write_frame(socket, TAG_TASK, &task.encode())?;
                    let (tag, payload) = read_frame(socket)?;
                    ensure!(tag == TAG_RESULT, "unexpected worker response");
                    let result = TaskResult::decode(&payload)?;
                    ensure!(result.worker_id == wid && result.task_id == task.task_id
                            && result.attempt == task.attempt, "response identity mismatch");
                    let proof = ProofWithPublicInputs::<F, C, D>::from_bytes(result.proof.clone(), &gc.data.common)?;
                    let mut expected = task.block_id.elements.to_vec();
                    expected.push(F::from_canonical_u64(task.group_index));
                    expected.extend(gc.circuit_id.elements);
                    expected.push(F::from_canonical_usize(gc.k_max));
                    expected.extend(group_digest(&task.txs, gc.k_max).elements);
                    expected.push(F::from_canonical_usize(task.txs.len()));
                    ensure!(proof.public_inputs == expected, "group statement mismatch");
                    gc.data.verify(proof)?;
                    ensure!(result.prove_ms.is_finite() && result.prove_ms > 0.0, "invalid observation");
                    results.push((task.clone(), result));
                }
                Ok(results)
            })
        }).collect();
        let mut result = Vec::new();
        for handle in handles { result.extend(handle.join().map_err(|_| anyhow::anyhow!("worker thread panicked"))??); }
        Ok(result)
    })
}

fn set_pace(sockets: &mut [TcpStream], factors: [f64; 2]) -> Result<()> {
    for (socket, factor) in sockets.iter_mut().zip(factors) { write_frame(socket, PACE, &factor.to_le_bytes())?; }
    Ok(())
}

fn probe(sockets: &mut [TcpStream], gc: &GroupCircuit, seed: u64) -> Result<Vec<(Task, TaskResult)>> {
    let b = make_block(seed, gc.k_max, gc.k_max);
    let task = Task { task_id: 0, attempt: 0, block_id: b.tx_root, group_index: 0,
        circuit_budget: gc.k_max, circuit_id: gc.circuit_id, predicted_ms: 1.0,
        txs: b.groups[0].clone(), sigs: b.sigs[0].clone() };
    execute(sockets, &[vec![task.clone()], vec![task]], gc)
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--worker") {
        ensure!(args.len() == 5, "worker arguments");
        return worker(&args[2], args[3].parse()?, args[4].parse()?);
    }
    ensure!(args.len() == 5, "usage: pcb_adaptation_bench output profile repetitions cpus");
    let out = PathBuf::from(&args[1]);
    ensure!(!out.exists(), "output exists");
    let reps: usize = args[3].parse()?;
    ensure!(reps > 0 && reps % 3 == 0, "three-policy position balancing requires a multiple of three");
    let cpus: Vec<usize> = args[4].split(',').map(str::parse).collect::<std::result::Result<_, _>>()?;
    ensure!(cpus.len() == 2 && cpus[0] != cpus[1], "two distinct CPUs required");
    let g = 4;
    let k = 16;
    let cm = CostModel::from_fixed_circuit_csv(&args[2], g)?;
    let gc = build_group_circuit(g);
    let identifier: String = gc.circuit_id.elements.iter().map(|x| format!("{:016x}", x.to_canonical_u64())).collect();
    ensure!(cm.circuit_id == identifier, "calibration circuit mismatch");
    std::fs::create_dir_all(&out)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?.to_string();
    let mut children = Children(Vec::new());
    for (id, cpu) in cpus.iter().enumerate() {
        children.0.push(Command::new("taskset").args(["-c", &cpu.to_string()])
            .arg(std::env::current_exe()?).args(["--worker", &address, &id.to_string(), &g.to_string()])
            .env("RAYON_NUM_THREADS", "1").spawn()?);
    }
    let mut slots: Vec<Option<TcpStream>> = vec![None, None];
    let deadline = Instant::now() + Duration::from_secs(180);
    while slots.iter().any(Option::is_none) {
        ensure!(Instant::now() < deadline, "worker startup timeout");
        match listener.accept() {
            Ok((mut socket, _)) => {
                socket.set_read_timeout(Some(Duration::from_secs(180)))?;
                socket.set_write_timeout(Some(Duration::from_secs(180)))?;
                socket.set_nodelay(true)?;
                let (tag, payload) = read_frame(&mut socket)?;
                ensure!(tag == TAG_READY && payload.len() == 8, "invalid worker greeting");
                let id = u64::from_le_bytes(payload.try_into().unwrap()) as usize;
                ensure!(id < 2 && slots[id].is_none(), "duplicate worker");
                slots[id] = Some(socket);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => return Err(e.into()),
        }
    }
    let mut sockets: Vec<_> = slots.into_iter().map(Option::unwrap).collect();
    let mut blocks = std::fs::File::create(out.join("blocks.csv"))?;
    let mut observations = std::fs::File::create(out.join("observations.csv"))?;
    writeln!(blocks, "rep,position,policy,block,seed,worker0_factor,worker1_factor,worker0_groups,worker1_groups,calibration_ms,planning_ms,validated_groups_ms,total_ms,updates,verified")?;
    writeln!(observations, "rep,policy,block,kind,worker,task,predicted_ms,measured_ms,profile_after_ms,verified")?;
    for rep in 1..=reps {
        set_pace(&mut sockets, [1.0, 2.0])?;
        let mut initial: Vec<Vec<f64>> = vec![Vec::new(), Vec::new()];
        for p in 0..=3 {
            for (_, result) in probe(&mut sockets, &gc, 202609231000 + rep as u64 * 10 + p)? {
                writeln!(observations, "{rep},initial,0,probe,{},{p},0,{:.6},{:.6},true", result.worker_id, result.prove_ms, result.prove_ms)?;
                if p > 0 { initial[result.worker_id].push(result.prove_ms); }
            }
        }
        let profiles: Vec<_> = initial.iter_mut().map(|values| {
            values.sort_by(f64::total_cmp);
            let mut p = cm.reference_profile("paired initial full-group probes");
            p.occupancies = vec![g]; p.prove_ms = vec![values[1]];
            p.peak_mb = vec![cm.peak_mb.iter().copied().fold(0.0, f64::max)];
            p.proof_bytes = vec![*cm.proof_bytes.last().unwrap()]; p.verify_ms = vec![*cm.verify_ms.last().unwrap()];
            p
        }).collect();
        for position in 0..3 {
            let policy = ["static", "ewma", "periodic"][(position + rep - 1) % 3];
            let mut workers: Vec<_> = (0..2).map(|i| {
                let mut w = Worker::homogeneous(i, 4096.0); w.profile = Some(profiles[i].clone()); w
            }).collect();
            for block in 1..=12 {
                let factors = [if (5..=8).contains(&block) { 4.0 } else { 1.0 }, 2.0];
                set_pace(&mut sockets, factors)?;
                let start = Instant::now();
                if policy == "periodic" && [4, 7, 10].contains(&block) {
                    for (_, result) in probe(&mut sockets, &gc, 202609232000 + (rep * 100 + block) as u64)? {
                        workers[result.worker_id].profile.as_mut().unwrap().prove_ms[0] = result.prove_ms;
                        writeln!(observations, "{rep},{policy},{block},probe,{},0,0,{:.6},{:.6},true", result.worker_id, result.prove_ms, result.prove_ms)?;
                    }
                }
                let calibration_ms = milliseconds(start);
                let seed = 202609233000 + (rep * 100 + block) as u64;
                let built = make_block(seed, k, g);
                let begin = Instant::now();
                let plan = plan_earliest_finish(k, &workers, &cm, g);
                validate_plan(&plan, &workers, &cm)?;
                let planning_ms = milliseconds(begin);
                let txs: Vec<_> = built.groups.iter().flatten().copied().collect();
                let sigs: Vec<_> = built.sigs.iter().flatten().cloned().collect();
                let mut tasks = vec![Vec::new(), Vec::new()];
                let mut offset = 0;
                for (j, &(n, wid)) in plan.groups.iter().enumerate() {
                    ensure!(n == g, "adaptation experiment requires full groups");
                    tasks[wid].push(Task { task_id: j, attempt: 0, block_id: built.tx_root, group_index: j as u64,
                        circuit_budget: g, circuit_id: gc.circuit_id, predicted_ms: cm.prove_ms_on(n, &workers[wid]),
                        txs: txs[offset..offset+n].to_vec(), sigs: sigs[offset..offset+n].to_vec() });
                    offset += n;
                }
                let begin = Instant::now();
                let results = execute(&mut sockets, &tasks, &gc)?;
                let elapsed = milliseconds(begin);
                let mut updates = 0;
                for (task, result) in results {
                    let p = workers[result.worker_id].profile.as_mut().unwrap();
                    if policy == "ewma" && p.observe(g, result.prove_ms, 0.20) { updates += 1; }
                    writeln!(observations, "{rep},{policy},{block},work,{},{},{:.6},{:.6},{:.6},true",
                        result.worker_id, task.task_id, task.predicted_ms, result.prove_ms, p.prove_ms[0])?;
                }
                let total = calibration_ms + planning_ms + elapsed;
                writeln!(blocks, "{rep},{position},{policy},{block},{seed},{},{},{},{},{calibration_ms:.6},{planning_ms:.6},{elapsed:.6},{total:.6},{updates},true",
                    factors[0], factors[1], tasks[0].len(), tasks[1].len())?;
                blocks.flush()?; observations.flush()?;
                eprintln!("adaptation rep={rep} policy={policy} block={block} total_ms={total:.1}");
            }
        }
    }
    for socket in &mut sockets { write_frame(socket, TAG_SHUTDOWN, &[])?; }
    for child in &mut children.0 { ensure!(child.wait()?.success(), "worker failed"); }
    Ok(())
}
