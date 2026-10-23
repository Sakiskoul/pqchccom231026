use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use pcb_recursive::mem::peak_working_set_mb;
use pcb_recursive::net::{read_frame, write_frame, Hello, Task, TaskResult, TAG_HELLO, TAG_READY, TAG_RESULT, TAG_SHUTDOWN, TAG_TASK};
use pcb_recursive::pcc::{build_group_circuit, make_block, prove_group};

#[cfg(windows)]
fn pin_to_cores(mask: usize) -> anyhow::Result<()> {
    use winapi::um::processthreadsapi::GetCurrentProcess;
    use winapi::um::winbase::SetProcessAffinityMask;
    anyhow::ensure!(
        mask <= u32::MAX as usize,
        "worker affinity mask exceeds the Windows API width"
    );
    let ok = unsafe { SetProcessAffinityMask(GetCurrentProcess(), mask as u32) };
    anyhow::ensure!(ok != 0, "failed to set worker affinity mask {mask:#x}");
    Ok(())
}
#[cfg(not(windows))]
fn pin_to_cores(_mask: usize) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(windows)]
fn current_affinity_mask(_configured: usize) -> u64 {
    use winapi::um::processthreadsapi::GetCurrentProcess;
    use winapi::um::winbase::GetProcessAffinityMask;
    let mut process_mask = 0usize;
    let mut system_mask = 0usize;
    let ok = unsafe {
        GetProcessAffinityMask(GetCurrentProcess(), &mut process_mask, &mut system_mask)
    };
    if ok == 0 {
        0
    } else {
        process_mask as u64
    }
}

#[cfg(not(windows))]
fn current_affinity_mask(configured: usize) -> u64 {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return configured as u64;
    };
    let Some(spec) = status
        .lines()
        .find_map(|line| line.strip_prefix("Cpus_allowed_list:"))
    else {
        return configured as u64;
    };
    let mut mask = 0u64;
    for part in spec.trim().split(',') {
        let mut bounds = part.split('-').filter_map(|value| value.parse::<usize>().ok());
        let Some(start) = bounds.next() else { continue };
        let end = bounds.next().unwrap_or(start);
        for cpu in start..=end.min(63) {
            mask |= 1u64 << cpu;
        }
    }
    if mask == 0 { configured as u64 } else { mask }
}

struct FaultSpec {
    kind: String,
    occurrence: usize,
    value: f64,
}

fn parse_fault(s: &str) -> FaultSpec {
    let parts: Vec<&str> = s.split(':').collect();
    let kind = parts.first().copied().unwrap_or("none").to_string();
    if kind == "slow" {
        return FaultSpec {
            kind,
            occurrence: 0,
            value: parts.get(1).and_then(|v| v.parse().ok()).unwrap_or(1.0),
        };
    }
    FaultSpec {
        kind,
        occurrence: parts.get(1).and_then(|v| v.parse().ok()).unwrap_or(1),
        value: parts.get(2).and_then(|v| v.parse().ok()).unwrap_or(0.0),
    }
}

fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().collect();
    let addr = a.get(1).cloned().unwrap_or_else(|| "127.0.0.1:9099".into());
    let worker_id: usize = a.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
    let g: usize = a.get(3).and_then(|s| s.parse().ok()).unwrap_or(2);
    let mem_mb: f64 = a.get(4).and_then(|s| s.parse().ok()).unwrap_or(4096.0);
    let fault_spec = a.get(5).cloned().unwrap_or_else(|| "none".into());
    let cores: usize = a.get(6).and_then(|s| s.parse().ok()).unwrap_or(1);
    let core_offset: usize = a.get(7).and_then(|s| s.parse().ok()).unwrap_or(worker_id);

    let fault = parse_fault(&fault_spec);
    let ncpu = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(8);
    let phys = |j: usize| -> usize { ((j * 2) % ncpu + (j * 2) / ncpu) % ncpu };
    let mut mask = 0usize;
    for c in 0..cores {
        mask |= 1 << phys(core_offset * cores + c);
    }
    anyhow::ensure!(mask != 0, "worker affinity mask is empty");
    pin_to_cores(mask)?;
    let affinity_mask = current_affinity_mask(mask);
    #[cfg(windows)]
    anyhow::ensure!(
        affinity_mask == mask as u64,
        "worker affinity does not match the requested mask"
    );
    #[cfg(not(windows))]
    anyhow::ensure!(affinity_mask != 0, "worker affinity could not be observed");

    let t0 = Instant::now();
    let gc = build_group_circuit(g);
    let build_ms = t0.elapsed().as_secs_f64() * 1000.0;

    let mut s = TcpStream::connect(&addr)?;
    s.set_nodelay(true)?;
    let hello = Hello {
        worker_id,
        mem_mb,
        cores,
        affinity_mask,
        fault: fault_spec.clone(),
        build_ms,
    };
    write_frame(&mut s, TAG_HELLO, &hello.encode())?;

    let mut received = 0usize;
    loop {
        let (tag, payload) = match read_frame(&mut s) {
            Ok(v) => v,
            Err(_) => break,
        };
        match tag {
            TAG_SHUTDOWN => break,
            TAG_TASK => {
                let task = Task::decode(&payload)?;
                anyhow::ensure!(
                    task.circuit_budget == g && task.circuit_id == gc.circuit_id,
                    "task targets a different group circuit"
                );
                anyhow::ensure!(
                    !task.txs.is_empty() && task.txs.len() <= g,
                    "task occupancy is outside the fixed circuit budget"
                );
                received += 1;
                let fires = received == fault.occurrence;
                if (fault.kind == "crash" || fault.kind == "crash-before") && fires {
                    eprintln!("worker {worker_id}: injected crash on task {}", task.task_id);
                    std::process::exit(1);
                }
                if fault.kind == "timeout" && fires {
                    eprintln!("worker {worker_id}: injected hang on task {}", task.task_id);
                    loop {
                        std::thread::sleep(Duration::from_secs(3600));
                    }
                }
                if fault.kind == "timeoutpct" && fires {
                    let delay = task.predicted_ms * fault.value.clamp(0.0, 100.0) / 100.0;
                    std::thread::sleep(Duration::from_millis(delay.max(0.0) as u64));
                    eprintln!(
                        "worker {worker_id}: injected timed hang at {:.0}% of task {}",
                        fault.value, task.task_id
                    );
                    loop {
                        std::thread::sleep(Duration::from_secs(3600));
                    }
                }
                if fault.kind == "late" && fires {
                    std::thread::sleep(Duration::from_millis(fault.value.max(0.0) as u64));
                }

                let proof_finished = Arc::new(AtomicBool::new(false));
                if fault.kind == "crashpct" && fires {
                    let finished = Arc::clone(&proof_finished);
                    let delay = task.predicted_ms * fault.value.clamp(0.0, 100.0) / 100.0;
                    let task_id = task.task_id;
                    std::thread::spawn(move || {
                        std::thread::sleep(Duration::from_millis(delay.max(0.0) as u64));
                        if !finished.load(Ordering::SeqCst) {
                            eprintln!("injected crash at {:.0}% of task {task_id}", fault.value);
                            std::process::exit(1);
                        }
                    });
                }
                if fault.kind == "disconnectpct" && fires {
                    let finished = Arc::clone(&proof_finished);
                    let delay = task.predicted_ms * fault.value.clamp(0.0, 100.0) / 100.0;
                    let cut = s.try_clone()?;
                    std::thread::spawn(move || {
                        std::thread::sleep(Duration::from_millis(delay.max(0.0) as u64));
                        if !finished.load(Ordering::SeqCst) {
                            let _ = cut.shutdown(Shutdown::Both);
                        }
                    });
                }
                let t = Instant::now();
                let proof = if (fault.kind == "invalid" || fault.kind == "byzantine") && fires {
                    let bb = make_block(0xDEAD_BEEF, task.txs.len().max(1), g);
                    prove_group(&gc, task.block_id, task.group_index + 1, &bb.groups[0], &bb.sigs[0])?
                } else {
                    prove_group(&gc, task.block_id, task.group_index, &task.txs, &task.sigs)?
                };
                let mut prove_ms = t.elapsed().as_secs_f64() * 1000.0;
                proof_finished.store(true, Ordering::SeqCst);
                if fault.kind == "slow" && fault.value > 1.0 {
                    let extra = prove_ms * (fault.value - 1.0);
                    std::thread::sleep(Duration::from_millis(extra as u64));
                    prove_ms += extra;
                }
                let mut proof_bytes = proof.to_bytes();
                if fault.kind == "corrupt" && fires && !proof_bytes.is_empty() {
                    let i = proof_bytes.len() / 2;
                    proof_bytes[i] ^= 0xff;
                }
                let res = TaskResult {
                    task_id: task.task_id,
                    attempt: task.attempt,
                    worker_id,
                    prove_ms,
                    peak_mb: peak_working_set_mb(),
                    proof: proof_bytes,
                };
                write_frame(&mut s, TAG_RESULT, &res.encode())?;
                if fault.kind == "duplicate" && fires {
                    write_frame(&mut s, TAG_RESULT, &res.encode())?;
                }
                if fault.kind == "byzantine" && fires {
                    let mut second = res.clone();
                    if !second.proof.is_empty() {
                        let i = second.proof.len() / 3;
                        second.proof[i] ^= 0xa5;
                    }
                    write_frame(&mut s, TAG_RESULT, &second.encode())?;
                }
            }
            TAG_READY => {}
            _ => {}
        }
    }
    Ok(())
}
