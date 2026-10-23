use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::hash_types::{HashOut, HashOutTarget};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::Hasher;

pub type F = GoldilocksField;
pub const D: usize = 2;
pub const W: usize = 16;
pub const WM1: usize = W - 1;

fn h(x: HashOut<F>) -> HashOut<F> {
    PoseidonHash::hash_no_pad(&x.elements)
}

fn chain(mut x: HashOut<F>, n: usize) -> HashOut<F> {
    for _ in 0..n {
        x = h(x);
    }
    x
}

fn sk_element(seed: u64, i: usize) -> HashOut<F> {
    let pre = [
        F::from_canonical_u64(seed),
        F::from_canonical_u64(i as u64),
        F::from_canonical_u64(0xA5A5_A5A5),
        F::from_canonical_u64(0x5A5A_5A5A),
    ];
    PoseidonHash::hash_no_pad(&pre)
}

pub struct Keypair {
    pub sk: Vec<HashOut<F>>,
    pub pk: HashOut<F>,
    pub l: usize,
}

pub fn keygen(seed: u64, l: usize) -> Keypair {
    let sk: Vec<HashOut<F>> = (0..l).map(|i| sk_element(seed, i)).collect();
    let ends: Vec<HashOut<F>> = sk.iter().map(|&s| chain(s, WM1)).collect();
    let flat: Vec<F> = ends.iter().flat_map(|e| e.elements).collect();
    let pk = PoseidonHash::hash_no_pad(&flat);
    Keypair { sk, pk, l }
}

pub fn sign(kp: &Keypair, digits: &[usize]) -> Vec<HashOut<F>> {
    assert_eq!(digits.len(), kp.l);
    assert!(
        digits.iter().all(|&d| d <= WM1),
        "WOTS digit outside the base-w range"
    );
    kp.sk.iter().zip(digits).map(|(&s, &d)| chain(s, d)).collect()
}

fn checksum_len(n1: usize) -> usize {
    let mut v = n1 * (W - 1);
    if v == 0 {
        return 1;
    }
    let mut n = 0;
    while v > 0 {
        v /= W;
        n += 1;
    }
    n
}

pub fn digits_from(msg: u64, l: usize) -> Vec<usize> {
    let mut n1 = l;
    while n1 > 0 && n1 + checksum_len(n1) != l {
        n1 -= 1;
    }
    let n2 = l - n1;

    let hdr = PoseidonHash::hash_no_pad(&[
        F::from_canonical_u64(msg),
        F::from_canonical_u64(0x00D1_6175),
    ]);
    let mut md: Vec<usize> = Vec::with_capacity(n1);
    'outer: for e in hdr.elements {
        let mut x = e.to_canonical_u64();
        for _ in 0..16 {
            if md.len() == n1 {
                break 'outer;
            }
            md.push((x & 0xF) as usize);
            x >>= 4;
        }
    }
    while md.len() < n1 {
        md.push(0);
    }

    let c: usize = md.iter().map(|&d| (W - 1) - d).sum();
    let mut digits = md;
    let mut cc = c;
    for _ in 0..n2 {
        digits.push(cc % W);
        cc /= W;
    }
    digits
}

pub fn recover_pk(digits: &[usize], sigma: &[HashOut<F>]) -> HashOut<F> {
    assert_eq!(
        digits.len(),
        sigma.len(),
        "one WOTS digit is required per chain value"
    );
    assert!(
        digits.iter().all(|&d| d <= WM1),
        "WOTS digit outside the base-w range"
    );
    let ends: Vec<HashOut<F>> = sigma.iter().zip(digits).map(|(&s, &d)| chain(s, WM1 - d)).collect();
    let flat: Vec<F> = ends.iter().flat_map(|e| e.elements).collect();
    PoseidonHash::hash_no_pad(&flat)
}

pub fn verify(pk: HashOut<F>, digits: &[usize], sigma: &[HashOut<F>]) -> bool {
    if digits.len() != sigma.len() || digits.iter().any(|&d| d > WM1) {
        return false;
    }
    recover_pk(digits, sigma) == pk
}

pub fn node_hash(l: HashOut<F>, r: HashOut<F>) -> HashOut<F> {
    let mut v = l.elements.to_vec();
    v.extend_from_slice(&r.elements);
    PoseidonHash::hash_no_pad(&v)
}

pub struct Xmss {
    pub leaves: Vec<HashOut<F>>,
    pub keys: Vec<Keypair>,
    pub root: HashOut<F>,
    pub h: usize,
    pub l: usize,
}

pub fn xmss_keygen(seed: u64, h: usize, l: usize) -> Xmss {
    assert!(
        h < usize::BITS as usize,
        "XMSS tree height exceeds the host index width"
    );
    assert!(l > 0, "XMSS requires at least one WOTS chain");
    let n = 1usize << h;
    let keys: Vec<Keypair> = (0..n).map(|i| keygen(seed.wrapping_add((i as u64) * 0x100), l)).collect();
    let leaves: Vec<HashOut<F>> = keys.iter().map(|kp| kp.pk).collect();
    let mut level = leaves.clone();
    while level.len() > 1 {
        level = level.chunks(2).map(|c| node_hash(c[0], c[1])).collect();
    }
    Xmss { leaves, keys, root: level[0], h, l }
}

pub fn xmss_auth_path(x: &Xmss, index: usize) -> Vec<HashOut<F>> {
    assert!(index < x.leaves.len(), "XMSS leaf index outside the tree");
    let mut path = Vec::with_capacity(x.h);
    let mut level = x.leaves.clone();
    let mut idx = index;
    while level.len() > 1 {
        path.push(level[idx ^ 1]);
        level = level.chunks(2).map(|c| node_hash(c[0], c[1])).collect();
        idx >>= 1;
    }
    path
}

pub fn xmss_verify(
    root: HashOut<F>,
    digits: &[usize],
    sigma: &[HashOut<F>],
    auth_path: &[HashOut<F>],
    index: usize,
) -> bool {
    if digits.len() != sigma.len()
        || digits.iter().any(|&d| d > WM1)
        || auth_path.len() >= usize::BITS as usize
        || index >= (1usize << auth_path.len())
    {
        return false;
    }
    let mut node = recover_pk(digits, sigma);
    let mut idx = index;
    for &sib in auth_path {
        node = if idx & 1 == 0 { node_hash(node, sib) } else { node_hash(sib, node) };
        idx >>= 1;
    }
    node == root
}

fn verify_chain_target(
    b: &mut CircuitBuilder<F, D>,
    sigma: HashOutTarget,
    d: Target,
) -> HashOutTarget {
    let mut hs: Vec<HashOutTarget> = Vec::with_capacity(W);
    hs.push(sigma);
    for k in 1..=WM1 {
        let prev = hs[k - 1];
        let next = b.hash_n_to_hash_no_pad::<PoseidonHash>(prev.elements.to_vec());
        hs.push(next);
    }
    b.range_check(d, 4);
    let wm1 = b.constant(F::from_canonical_u64(WM1 as u64));
    let idx = b.sub(wm1, d);
    let mut out = [b.zero(); 4];
    for j in 0..4 {
        let column: Vec<Target> = hs.iter().map(|hh| hh.elements[j]).collect();
        out[j] = b.random_access(idx, column);
    }
    HashOutTarget { elements: out }
}

pub struct GroupTargets {
    pub pks: Vec<HashOutTarget>,
    pub digits: Vec<Vec<Target>>,
    pub sigmas: Vec<Vec<HashOutTarget>>,
}

pub fn build_group_circuit(
    b: &mut CircuitBuilder<F, D>,
    k: usize,
    l: usize,
) -> GroupTargets {
    let mut pks = Vec::with_capacity(k);
    let mut digits = Vec::with_capacity(k);
    let mut sigmas = Vec::with_capacity(k);

    for _ in 0..k {
        let pk = b.add_virtual_hash();
        for e in pk.elements {
            b.register_public_input(e);
        }
        let mut dig = Vec::with_capacity(l);
        for _ in 0..l {
            let d = b.add_virtual_target();
            b.register_public_input(d);
            dig.push(d);
        }
        let mut sig = Vec::with_capacity(l);
        let mut ends_flat: Vec<Target> = Vec::with_capacity(l * 4);
        for j in 0..l {
            let s = b.add_virtual_hash();
            let end = verify_chain_target(b, s, dig[j]);
            ends_flat.extend_from_slice(&end.elements);
            sig.push(s);
        }
        let pk_prime = b.hash_n_to_hash_no_pad::<PoseidonHash>(ends_flat);
        for j in 0..4 {
            b.connect(pk_prime.elements[j], pk.elements[j]);
        }
        pks.push(pk);
        digits.push(dig);
        sigmas.push(sig);
    }

    GroupTargets { pks, digits, sigmas }
}

fn recover_wots_pk_target(
    b: &mut CircuitBuilder<F, D>,
    sigma: &[HashOutTarget],
    digits: &[Target],
) -> HashOutTarget {
    let mut ends_flat: Vec<Target> = Vec::with_capacity(sigma.len() * 4);
    for (s, &d) in sigma.iter().zip(digits) {
        let end = verify_chain_target(b, *s, d);
        ends_flat.extend_from_slice(&end.elements);
    }
    b.hash_n_to_hash_no_pad::<PoseidonHash>(ends_flat)
}

pub struct XmssTargets {
    pub roots: Vec<HashOutTarget>,
    pub digits: Vec<Vec<Target>>,
    pub index_bits: Vec<Vec<BoolTarget>>,
    pub sigmas: Vec<Vec<HashOutTarget>>,
    pub paths: Vec<Vec<HashOutTarget>>,
}

pub fn build_xmss_group_circuit(
    b: &mut CircuitBuilder<F, D>,
    k: usize,
    l: usize,
    h: usize,
) -> XmssTargets {
    assert!(
        h < usize::BITS as usize,
        "XMSS tree height exceeds the host index width"
    );
    let mut roots = Vec::with_capacity(k);
    let mut digits = Vec::with_capacity(k);
    let mut index_bits = Vec::with_capacity(k);
    let mut sigmas = Vec::with_capacity(k);
    let mut paths = Vec::with_capacity(k);

    for _ in 0..k {
        let root = b.add_virtual_hash();
        for e in root.elements {
            b.register_public_input(e);
        }
        let mut dig = Vec::with_capacity(l);
        for _ in 0..l {
            let d = b.add_virtual_target();
            b.register_public_input(d);
            dig.push(d);
        }
        let mut sig = Vec::with_capacity(l);
        for _ in 0..l {
            sig.push(b.add_virtual_hash());
        }
        let leaf = recover_wots_pk_target(b, &sig, &dig);

        let mut bits = Vec::with_capacity(h);
        let mut path = Vec::with_capacity(h);
        let mut node = leaf;
        for _ in 0..h {
            let bit = b.add_virtual_bool_target_safe();
            b.register_public_input(bit.target);
            let sib = b.add_virtual_hash();
            let mut left = [b.zero(); 4];
            let mut right = [b.zero(); 4];
            for j in 0..4 {
                left[j] = b.select(bit, sib.elements[j], node.elements[j]);
                right[j] = b.select(bit, node.elements[j], sib.elements[j]);
            }
            let mut inp = left.to_vec();
            inp.extend_from_slice(&right);
            node = b.hash_n_to_hash_no_pad::<PoseidonHash>(inp);
            bits.push(bit);
            path.push(sib);
        }
        for j in 0..4 {
            b.connect(node.elements[j], root.elements[j]);
        }

        roots.push(root);
        digits.push(dig);
        index_bits.push(bits);
        sigmas.push(sig);
        paths.push(path);
    }

    XmssTargets { roots, digits, index_bits, sigmas, paths }
}

pub fn fill_xmss_witness(
    pw: &mut PartialWitness<F>,
    t: &XmssTargets,
    roots: &[HashOut<F>],
    digits: &[Vec<usize>],
    sigmas: &[Vec<HashOut<F>>],
    paths: &[Vec<HashOut<F>>],
    indices: &[usize],
) {
    let k = t.roots.len();
    assert_eq!(roots.len(), k);
    assert_eq!(digits.len(), k);
    assert_eq!(sigmas.len(), k);
    assert_eq!(paths.len(), k);
    assert_eq!(indices.len(), k);
    for s in 0..k {
        assert_eq!(digits[s].len(), t.digits[s].len());
        assert_eq!(sigmas[s].len(), t.sigmas[s].len());
        assert_eq!(paths[s].len(), t.paths[s].len());
        assert!(indices[s] < (1usize << t.index_bits[s].len()));
        let _ = pw.set_hash_target(t.roots[s], roots[s]);
        for (dt, &dv) in t.digits[s].iter().zip(&digits[s]) {
            let _ = pw.set_target(*dt, F::from_canonical_u64(dv as u64));
        }
        for (st, &sv) in t.sigmas[s].iter().zip(&sigmas[s]) {
            let _ = pw.set_hash_target(*st, sv);
        }
        for (pt, &pv) in t.paths[s].iter().zip(&paths[s]) {
            let _ = pw.set_hash_target(*pt, pv);
        }
        for (lv, bt) in t.index_bits[s].iter().enumerate() {
            let _ = pw.set_bool_target(*bt, (indices[s] >> lv) & 1 == 1);
        }
    }
}

pub fn fill_group_witness(
    pw: &mut PartialWitness<F>,
    t: &GroupTargets,
    pks: &[HashOut<F>],
    digits: &[Vec<usize>],
    sigmas: &[Vec<HashOut<F>>],
) {
    let k = t.pks.len();
    assert_eq!(pks.len(), k);
    assert_eq!(digits.len(), k);
    assert_eq!(sigmas.len(), k);
    for s in 0..k {
        assert_eq!(digits[s].len(), t.digits[s].len());
        assert_eq!(sigmas[s].len(), t.sigmas[s].len());
        let _ = pw.set_hash_target(t.pks[s], pks[s]);
        for (dt, &dv) in t.digits[s].iter().zip(&digits[s]) {
            let _ = pw.set_target(*dt, F::from_canonical_u64(dv as u64));
        }
        for (st, &sv) in t.sigmas[s].iter().zip(&sigmas[s]) {
            let _ = pw.set_hash_target(*st, sv);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_verifiers_reject_malformed_lengths_and_indices() {
        let kp = keygen(7, 4);
        let digits = vec![0, 1, 2, 3];
        let signature = sign(&kp, &digits);
        assert!(verify(kp.pk, &digits, &signature));
        assert!(!verify(kp.pk, &digits[..3], &signature));

        let xmss = xmss_keygen(9, 2, 4);
        let path = xmss_auth_path(&xmss, 0);
        let xmss_signature = sign(&xmss.keys[0], &digits);
        assert!(xmss_verify(xmss.root, &digits, &xmss_signature, &path, 0));
        assert!(!xmss_verify(xmss.root, &digits, &xmss_signature, &path, 4));
        assert!(!xmss_verify(
            xmss.root,
            &digits,
            &xmss_signature,
            &path[..1],
            0
        ));
    }
}
