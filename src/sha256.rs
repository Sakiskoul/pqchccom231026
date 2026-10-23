use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;

pub type F = GoldilocksField;
pub const D: usize = 2;

pub const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

pub const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn compress_native(state: [u32; 8], block: [u32; 16]) -> [u32; 8] {
    let mut w = [0u32; 64];
    w[..16].copy_from_slice(&block);
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    [
        state[0].wrapping_add(a),
        state[1].wrapping_add(b),
        state[2].wrapping_add(c),
        state[3].wrapping_add(d),
        state[4].wrapping_add(e),
        state[5].wrapping_add(f),
        state[6].wrapping_add(g),
        state[7].wrapping_add(h),
    ]
}

pub fn sha256_native(msg: &[u8]) -> [u8; 32] {
    let mut padded = msg.to_vec();
    let bitlen = (msg.len() as u64) * 8;
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bitlen.to_be_bytes());
    let mut state = H0;
    for chunk in padded.chunks(64) {
        let mut block = [0u32; 16];
        for (i, w) in block.iter_mut().enumerate() {
            *w = u32::from_be_bytes(chunk[4 * i..4 * i + 4].try_into().unwrap());
        }
        state = compress_native(state, block);
    }
    let mut out = [0u8; 32];
    for (i, s) in state.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&s.to_be_bytes());
    }
    out
}

#[derive(Clone)]
pub struct U32Target {
    pub value: Target,
    pub bits: Vec<BoolTarget>,
}

fn bits_to_target(b: &mut CircuitBuilder<F, D>, bits: &[BoolTarget]) -> Target {
    let mut acc = b.zero();
    for (i, bit) in bits.iter().enumerate() {
        let w = b.constant(F::from_canonical_u64(1u64 << i));
        acc = b.mul_add(bit.target, w, acc);
    }
    acc
}

fn split32(b: &mut CircuitBuilder<F, D>, t: Target) -> U32Target {
    let bits = b.split_le(t, 32);
    U32Target { value: t, bits }
}

fn xor_bit(b: &mut CircuitBuilder<F, D>, x: BoolTarget, y: BoolTarget) -> BoolTarget {
    let xy = b.mul(x.target, y.target);
    let two = b.constant(F::TWO);
    let two_xy = b.mul(two, xy);
    let sum = b.add(x.target, y.target);
    let r = b.sub(sum, two_xy);
    BoolTarget::new_unsafe(r)
}

fn and_bit(b: &mut CircuitBuilder<F, D>, x: BoolTarget, y: BoolTarget) -> BoolTarget {
    BoolTarget::new_unsafe(b.mul(x.target, y.target))
}

fn not_bit(b: &mut CircuitBuilder<F, D>, x: BoolTarget) -> BoolTarget {
    let one = b.one();
    BoolTarget::new_unsafe(b.sub(one, x.target))
}

fn rotr(bits: &[BoolTarget], n: usize) -> Vec<BoolTarget> {
    (0..32).map(|i| bits[(i + n) % 32]).collect()
}

fn shr(b: &mut CircuitBuilder<F, D>, bits: &[BoolTarget], n: usize) -> Vec<BoolTarget> {
    let zero = b.zero();
    (0..32)
        .map(|i| if i + n < 32 { bits[i + n] } else { BoolTarget::new_unsafe(zero) })
        .collect()
}

fn xor3(
    b: &mut CircuitBuilder<F, D>,
    x: &[BoolTarget],
    y: &[BoolTarget],
    z: &[BoolTarget],
) -> Vec<BoolTarget> {
    (0..32)
        .map(|i| {
            let t = xor_bit(b, x[i], y[i]);
            xor_bit(b, t, z[i])
        })
        .collect()
}

fn add_mod32(b: &mut CircuitBuilder<F, D>, terms: &[Target]) -> U32Target {
    let mut sum = b.zero();
    for &t in terms {
        sum = b.add(sum, t);
    }
    let extra = 8;
    let bits = b.split_le(sum, 32 + extra);
    let low: Vec<BoolTarget> = bits[..32].to_vec();
    let value = bits_to_target(b, &low);
    U32Target { value, bits: low }
}

pub fn compress_target(
    b: &mut CircuitBuilder<F, D>,
    state: &[U32Target; 8],
    block: &[U32Target; 16],
) -> [U32Target; 8] {
    let mut w: Vec<U32Target> = block.to_vec();
    for i in 16..64 {
        let a = &w[i - 15];
        let s0 = {
            let r7 = rotr(&a.bits, 7);
            let r18 = rotr(&a.bits, 18);
            let s3 = shr(b, &a.bits, 3);
            xor3(b, &r7, &r18, &s3)
        };
        let c = &w[i - 2];
        let s1 = {
            let r17 = rotr(&c.bits, 17);
            let r19 = rotr(&c.bits, 19);
            let s10 = shr(b, &c.bits, 10);
            xor3(b, &r17, &r19, &s10)
        };
        let s0t = bits_to_target(b, &s0);
        let s1t = bits_to_target(b, &s1);
        let terms = [w[i - 16].value, s0t, w[i - 7].value, s1t];
        w.push(add_mod32(b, &terms));
    }

    let mut a = state[0].clone();
    let mut bb = state[1].clone();
    let mut c = state[2].clone();
    let mut d = state[3].clone();
    let mut e = state[4].clone();
    let mut f = state[5].clone();
    let mut g = state[6].clone();
    let mut h = state[7].clone();

    for (i, kw) in K.iter().enumerate() {
        let s1 = {
            let r6 = rotr(&e.bits, 6);
            let r11 = rotr(&e.bits, 11);
            let r25 = rotr(&e.bits, 25);
            xor3(b, &r6, &r11, &r25)
        };
        let ch: Vec<BoolTarget> = (0..32)
            .map(|j| {
                let ef = and_bit(b, e.bits[j], f.bits[j]);
                let ne = not_bit(b, e.bits[j]);
                let ng = and_bit(b, ne, g.bits[j]);
                xor_bit(b, ef, ng)
            })
            .collect();
        let s1t = bits_to_target(b, &s1);
        let cht = bits_to_target(b, &ch);
        let kc = b.constant(F::from_canonical_u64(*kw as u64));
        let t1 = add_mod32(b, &[h.value, s1t, cht, kc, w[i].value]);

        let s0 = {
            let r2 = rotr(&a.bits, 2);
            let r13 = rotr(&a.bits, 13);
            let r22 = rotr(&a.bits, 22);
            xor3(b, &r2, &r13, &r22)
        };
        let maj: Vec<BoolTarget> = (0..32)
            .map(|j| {
                let ab = and_bit(b, a.bits[j], bb.bits[j]);
                let ac = and_bit(b, a.bits[j], c.bits[j]);
                let bc = and_bit(b, bb.bits[j], c.bits[j]);
                let t = xor_bit(b, ab, ac);
                xor_bit(b, t, bc)
            })
            .collect();
        let s0t = bits_to_target(b, &s0);
        let majt = bits_to_target(b, &maj);
        let t2 = add_mod32(b, &[s0t, majt]);

        h = g;
        g = f;
        f = e;
        e = add_mod32(b, &[d.value, t1.value]);
        d = c;
        c = bb;
        bb = a;
        a = add_mod32(b, &[t1.value, t2.value]);
    }

    [
        add_mod32(b, &[state[0].value, a.value]),
        add_mod32(b, &[state[1].value, bb.value]),
        add_mod32(b, &[state[2].value, c.value]),
        add_mod32(b, &[state[3].value, d.value]),
        add_mod32(b, &[state[4].value, e.value]),
        add_mod32(b, &[state[5].value, f.value]),
        add_mod32(b, &[state[6].value, g.value]),
        add_mod32(b, &[state[7].value, h.value]),
    ]
}

pub fn constant_u32(b: &mut CircuitBuilder<F, D>, v: u32) -> U32Target {
    let t = b.constant(F::from_canonical_u64(v as u64));
    split32(b, t)
}

pub fn virtual_u32(b: &mut CircuitBuilder<F, D>) -> U32Target {
    let t = b.add_virtual_target();
    split32(b, t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;

    type C = PoseidonGoldilocksConfig;

    #[test]
    fn native_matches_published_vectors() {
        let d = sha256_native(b"abc");
        assert_eq!(
            hex(&d),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let e = sha256_native(b"");
        assert_eq!(
            hex(&e),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn circuit_matches_native_compression() {
        let mut msg = b"abc".to_vec();
        msg.push(0x80);
        while msg.len() % 64 != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&(24u64).to_be_bytes());
        let mut block = [0u32; 16];
        for (i, w) in block.iter_mut().enumerate() {
            *w = u32::from_be_bytes(msg[4 * i..4 * i + 4].try_into().unwrap());
        }
        let expect = compress_native(H0, block);

        let mut b = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let st: [U32Target; 8] = core::array::from_fn(|i| constant_u32(&mut b, H0[i]));
        let bl: [U32Target; 16] = core::array::from_fn(|_| virtual_u32(&mut b));
        let out = compress_target(&mut b, &st, &bl);
        for o in &out {
            b.register_public_input(o.value);
        }
        let data = b.build::<C>();

        let mut pw = PartialWitness::<F>::new();
        for (t, v) in bl.iter().zip(block.iter()) {
            pw.set_target(t.value, F::from_canonical_u64(*v as u64));
        }
        let proof = data.prove(pw).expect("sha256 compression prove");
        for (i, e) in expect.iter().enumerate() {
            assert_eq!(
                proof.public_inputs[i],
                F::from_canonical_u64(*e as u64),
                "word {i} mismatch"
            );
        }
        data.verify(proof).expect("sha256 compression verify");
    }
}
