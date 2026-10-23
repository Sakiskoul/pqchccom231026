use std::io::{self, ErrorKind, Read, Write};
use std::net::TcpStream;

use plonky2::field::types::{Field, Field64, PrimeField64};
use plonky2::hash::hash_types::HashOut;

use crate::pcc::{Tx, F, L};

pub const WIRE_U64_BYTES: usize = std::mem::size_of::<u64>();
pub const WIRE_HASH_BYTES: usize = 4 * WIRE_U64_BYTES;
pub const WIRE_LENGTH_BYTES: usize = WIRE_U64_BYTES;
pub const TX_WIRE_BYTES: usize = 2 * WIRE_HASH_BYTES + WIRE_U64_BYTES;
pub const WOTS_SIGNATURE_WIRE_BYTES: usize = L * WIRE_HASH_BYTES;
pub const WOTS_WITNESS_WIRE_BYTES_PER_TX: usize =
    TX_WIRE_BYTES + WIRE_LENGTH_BYTES + WOTS_SIGNATURE_WIRE_BYTES;

pub const TAG_HELLO: u8 = 1;
pub const TAG_TASK: u8 = 2;
pub const TAG_RESULT: u8 = 3;
pub const TAG_SHUTDOWN: u8 = 4;
pub const TAG_READY: u8 = 5;
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
const MAX_TASK_TRANSACTIONS: usize = 4096;
const MAX_FAULT_LABEL_BYTES: usize = 256;

fn finite_nonnegative(value: f64, field: &str) -> io::Result<f64> {
    if value.is_finite() && value >= 0.0 {
        Ok(value)
    } else {
        Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("{field} must be finite and non-negative"),
        ))
    }
}

pub fn write_frame(s: &mut TcpStream, tag: u8, payload: &[u8]) -> std::io::Result<usize> {
    if payload.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "frame exceeds the protocol limit",
        ));
    }
    let mut hdr = [0u8; 5];
    hdr[0] = tag;
    hdr[1..5].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    s.write_all(&hdr)?;
    s.write_all(payload)?;
    s.flush()?;
    Ok(hdr.len() + payload.len())
}

pub fn read_frame(s: &mut TcpStream) -> std::io::Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 5];
    s.read_exact(&mut hdr)?;
    let n = u32::from_le_bytes(hdr[1..5].try_into().unwrap()) as usize;
    if n > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "frame exceeds the protocol limit",
        ));
    }
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf)?;
    Ok((hdr[0], buf))
}

pub struct Enc(pub Vec<u8>);

impl Default for Enc {
    fn default() -> Self {
        Self::new()
    }
}

impl Enc {
    pub fn new() -> Self {
        Enc(Vec::new())
    }
    pub fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    pub fn usize(&mut self, v: usize) {
        self.u64(v as u64);
    }
    pub fn f64(&mut self, v: f64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    pub fn hash(&mut self, h: HashOut<F>) {
        for e in h.elements {
            self.u64(e.to_canonical_u64());
        }
    }
    pub fn bytes(&mut self, b: &[u8]) {
        self.usize(b.len());
        self.0.extend_from_slice(b);
    }
}

pub struct Dec<'a> {
    pub b: &'a [u8],
    pub i: usize,
}

impl<'a> Dec<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Dec { b, i: 0 }
    }
    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        let end = self
            .i
            .checked_add(n)
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "decoder offset overflow"))?;
        if end > self.b.len() {
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "truncated protocol payload",
            ));
        }
        let out = &self.b[self.i..end];
        self.i = end;
        Ok(out)
    }
    pub fn u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn usize(&mut self) -> io::Result<usize> {
        usize::try_from(self.u64()?)
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "integer does not fit usize"))
    }
    pub fn f64(&mut self) -> io::Result<f64> {
        Ok(f64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn hash(&mut self) -> io::Result<HashOut<F>> {
        let mut elements = [F::ZERO; 4];
        for element in &mut elements {
            let value = self.u64()?;
            if value >= F::ORDER {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "non-canonical field element in protocol payload",
                ));
            }
            *element = F::from_canonical_u64(value);
        }
        Ok(HashOut { elements })
    }
    pub fn bytes(&mut self) -> io::Result<Vec<u8>> {
        let n = self.usize()?;
        Ok(self.take(n)?.to_vec())
    }
    pub fn finish(self) -> io::Result<()> {
        if self.i == self.b.len() {
            Ok(())
        } else {
            Err(io::Error::new(
                ErrorKind::InvalidData,
                "trailing bytes in protocol payload",
            ))
        }
    }
}

#[derive(Clone, Debug)]
pub struct Hello {
    pub worker_id: usize,
    pub mem_mb: f64,
    pub cores: usize,
    pub affinity_mask: u64,
    pub fault: String,
    pub build_ms: f64,
}

impl Hello {
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.usize(self.worker_id);
        e.f64(self.mem_mb);
        e.usize(self.cores);
        e.u64(self.affinity_mask);
        e.bytes(self.fault.as_bytes());
        e.f64(self.build_ms);
        e.0
    }
    pub fn decode(b: &[u8]) -> io::Result<Hello> {
        let mut d = Dec::new(b);
        let worker_id = d.usize()?;
        let mem_mb = finite_nonnegative(d.f64()?, "worker memory")?;
        let cores = d.usize()?;
        let affinity_mask = d.u64()?;
        let fault_bytes = d.bytes()?;
        if fault_bytes.len() > MAX_FAULT_LABEL_BYTES {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "fault label exceeds the protocol limit",
            ));
        }
        let fault = String::from_utf8(fault_bytes)
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "fault label is not UTF-8"))?;
        let build_ms = finite_nonnegative(d.f64()?, "worker build time")?;
        if mem_mb == 0.0 || cores == 0 || cores > 64 {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "worker resources are outside protocol limits",
            ));
        }
        d.finish()?;
        Ok(Hello {
            worker_id,
            mem_mb,
            cores,
            affinity_mask,
            fault,
            build_ms,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Task {
    pub task_id: usize,
    pub attempt: usize,
    pub block_id: HashOut<F>,
    pub group_index: u64,
    pub circuit_budget: usize,
    pub circuit_id: HashOut<F>,
    pub predicted_ms: f64,
    pub txs: Vec<Tx>,
    pub sigs: Vec<Vec<HashOut<F>>>,
}

impl Task {
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.usize(self.task_id);
        e.usize(self.attempt);
        e.hash(self.block_id);
        e.u64(self.group_index);
        e.usize(self.circuit_budget);
        e.hash(self.circuit_id);
        e.f64(self.predicted_ms);
        e.usize(self.txs.len());
        for t in &self.txs {
            e.hash(t.pk);
            e.hash(t.msg);
            e.u64(t.index);
        }
        e.usize(self.sigs.len());
        for s in &self.sigs {
            e.usize(s.len());
            for h in s {
                e.hash(*h);
            }
        }
        e.0
    }
    pub fn decode(b: &[u8]) -> io::Result<Task> {
        let mut d = Dec::new(b);
        let task_id = d.usize()?;
        let attempt = d.usize()?;
        let block_id = d.hash()?;
        let group_index = d.u64()?;
        let circuit_budget = d.usize()?;
        let circuit_id = d.hash()?;
        let predicted_ms = finite_nonnegative(d.f64()?, "predicted proving time")?;
        let n = d.usize()?;
        if n == 0 || n > circuit_budget || circuit_budget > MAX_TASK_TRANSACTIONS {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "task occupancy or circuit budget is outside protocol limits",
            ));
        }
        let mut txs = Vec::with_capacity(n);
        for _ in 0..n {
            txs.push(Tx {
                pk: d.hash()?,
                msg: d.hash()?,
                index: d.u64()?,
            });
        }
        let m = d.usize()?;
        if m != n {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "task must carry one signature per transaction",
            ));
        }
        let mut sigs = Vec::with_capacity(m);
        for _ in 0..m {
            let l = d.usize()?;
            if l != L {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "unexpected WOTS signature length",
                ));
            }
            let mut signature = Vec::with_capacity(l);
            for _ in 0..l {
                signature.push(d.hash()?);
            }
            sigs.push(signature);
        }
        d.finish()?;
        Ok(Task {
            task_id,
            attempt,
            block_id,
            group_index,
            circuit_budget,
            circuit_id,
            predicted_ms,
            txs,
            sigs,
        })
    }
}

#[derive(Clone, Debug)]
pub struct TaskResult {
    pub task_id: usize,
    pub attempt: usize,
    pub worker_id: usize,
    pub prove_ms: f64,
    pub peak_mb: f64,
    pub proof: Vec<u8>,
}

impl TaskResult {
    pub fn encoded_len(&self) -> usize {
        6 * std::mem::size_of::<u64>() + self.proof.len()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.usize(self.task_id);
        e.usize(self.attempt);
        e.usize(self.worker_id);
        e.f64(self.prove_ms);
        e.f64(self.peak_mb);
        e.bytes(&self.proof);
        e.0
    }
    pub fn decode(b: &[u8]) -> io::Result<TaskResult> {
        let mut d = Dec::new(b);
        let task_id = d.usize()?;
        let attempt = d.usize()?;
        let worker_id = d.usize()?;
        let prove_ms = finite_nonnegative(d.f64()?, "reported proving time")?;
        let peak_mb = finite_nonnegative(d.f64()?, "reported peak memory")?;
        let proof = d.bytes()?;
        d.finish()?;
        Ok(TaskResult {
            task_id,
            attempt,
            worker_id,
            prove_ms,
            peak_mb,
            proof,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Dec, Hello, TaskResult};

    #[test]
    fn decoders_reject_truncated_and_trailing_payloads() {
        let hello = Hello {
            worker_id: 1,
            mem_mb: 1024.0,
            cores: 1,
            affinity_mask: 1,
            fault: "none".into(),
            build_ms: 2.0,
        }
        .encode();
        assert!(Hello::decode(&hello[..hello.len() - 1]).is_err());

        let mut result = TaskResult {
            task_id: 0,
            attempt: 0,
            worker_id: 1,
            prove_ms: 3.0,
            peak_mb: 4.0,
            proof: vec![1, 2, 3],
        }
        .encode();
        assert_eq!(result.len(), 6 * std::mem::size_of::<u64>() + 3);
        result.push(0);
        assert!(TaskResult::decode(&result).is_err());

        let noncanonical_hash = [0xff; 32];
        assert!(Dec::new(&noncanonical_hash).hash().is_err());
    }

    #[test]
    fn decoders_reject_nonfinite_worker_telemetry() {
        let hello = Hello {
            worker_id: 1,
            mem_mb: f64::NAN,
            cores: 1,
            affinity_mask: 1,
            fault: "none".into(),
            build_ms: 2.0,
        }
        .encode();
        assert!(Hello::decode(&hello).is_err());

        let result = TaskResult {
            task_id: 0,
            attempt: 0,
            worker_id: 1,
            prove_ms: f64::INFINITY,
            peak_mb: 4.0,
            proof: vec![1, 2, 3],
        }
        .encode();
        assert!(TaskResult::decode(&result).is_err());
    }
}
