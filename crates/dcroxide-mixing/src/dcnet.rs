// SPDX-License-Identifier: ISC
//! The DC-net message vectors and mixing math (dcrd mixing `vec.go`
//! and `dcnet.go`).

// Bounded message and vector arithmetic mirrors Go; genuinely
// wrapping math uses explicit wrapping operations.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_crypto::blake256;
use dcroxide_wire::MixVect;

use crate::field::{F, FieldInt};
use crate::prng::ChaCha20Prng;

/// The size of the message being mixed: the size of a HASH160, which
/// allows mixes to create either all P2PKH or P2SH outputs (dcrd
/// `Msize`).
pub const MSIZE: usize = 20;

/// A vector of [`MSIZE`]-byte messages (dcrd `Vec`); identical in
/// shape to the wire [`MixVect`].
pub type Vect = MixVect;

/// A vector of random messages read from the run PRNG (dcrd
/// `randVec`).
pub fn rand_vec(n: u32, prng: &mut ChaCha20Prng) -> Vect {
    let mut v = Vect::new();
    for _ in 0..n {
        let mut msg = [0u8; MSIZE];
        prng.read(&mut msg);
        v.push(msg);
    }
    v
}

/// Whether the two vectors have equal dimensions and data (dcrd
/// `Vec.Equals`).
pub fn vec_equals(v: &Vect, other: &Vect) -> bool {
    v == other
}

/// The debug representation of a vector (dcrd `Vec.String`).
pub fn vec_string(v: &Vect) -> String {
    let mut b = String::with_capacity(2 + v.len() * (2 * MSIZE + 1));
    b.push('[');
    for (i, msg) in v.iter().enumerate() {
        if i != 0 {
            b.push(' ');
        }
        for byte in msg {
            b.push_str(&format!("{byte:02x}"));
        }
    }
    b.push(']');
    b
}

/// Write the xor of each vector element of src1 and src2 into dst
/// (dcrd `Vec.Xor`).  Panics if vectors do not share identical
/// dimensions.
pub fn vec_xor(dst: &mut Vect, src1: &Vect, src2: &Vect) {
    assert!(
        dst.len() == src1.len() && dst.len() == src2.len(),
        "dcnet: vectors do not share identical dimensions"
    );
    for i in 0..dst.len() {
        for j in 0..MSIZE {
            dst[i][j] = src1[i][j] ^ src2[i][j];
        }
    }
}

/// The xor of all vectors (dcrd `XorVectors`).  Panics if vectors do
/// not share identical dimensions.
pub fn xor_vectors(vs: &[Vect]) -> Vect {
    let mut res = vec![[0u8; MSIZE]; vs[0].len()];
    for v in vs {
        let src = res.clone();
        vec_xor(&mut res, &src, v);
    }
    res
}

/// A vector of exponential DC-net pads from a vector of shared
/// secrets with each participating peer in the DC-net (dcrd
/// `SRMixPads`).
pub fn sr_mix_pads(kp: &[Vec<u8>], my: u32) -> Vec<FieldInt> {
    let mut pads = Vec::with_capacity(kp.len());
    for j in 0..kp.len() as u32 {
        let mut pad = FieldInt::ZERO;
        let scratch = (u64::from(j) + 1).to_le_bytes();
        for i in 0..kp.len() as u32 {
            if my == i {
                continue;
            }
            let mut preimage = Vec::with_capacity(kp[i as usize].len() + 8);
            preimage.extend_from_slice(&kp[i as usize]);
            preimage.extend_from_slice(&scratch);
            let digest = blake256::sum256(&preimage);
            let partial_pad = FieldInt::from_be_bytes(&digest);
            if my > i {
                pad = pad.add(&partial_pad);
            } else {
                pad = pad.sub(&partial_pad);
            }
        }
        pads.push(pad);
    }
    pads
}

/// The padded {m**1, m**2, ..., m**n} message exponentials vector
/// (dcrd `SRMix`).  The message must be bounded by the field prime
/// and must be unique to every exponential SR run in a mix session to
/// ensure anonymity.
pub fn sr_mix(m: &FieldInt, pads: &[FieldInt]) -> Vec<FieldInt> {
    let mut mix = Vec::with_capacity(pads.len());
    for (i, pad) in pads.iter().enumerate() {
        let mexp = m.pow(i as u128 + 1);
        mix.push(mexp.add(pad));
    }
    mix
}

/// A 2-dimensional field element slice from absolute values as bytes
/// (dcrd `IntVectorsFromBytes`); values are reduced to canonical
/// residues on entry.
pub fn int_vectors_from_bytes(vs: &[Vec<Vec<u8>>]) -> Vec<Vec<FieldInt>> {
    vs.iter()
        .map(|v| v.iter().map(|b| FieldInt::from_be_bytes(b)).collect())
        .collect()
}

/// A 2-dimensional slice of field element values as minimal
/// big-endian bytes (dcrd `IntVectorsToBytes`).
pub fn int_vectors_to_bytes(ints: &[Vec<FieldInt>]) -> Vec<Vec<Vec<u8>>> {
    ints.iter()
        .map(|v| v.iter().map(|x| x.to_be_bytes()).collect())
        .collect()
}

/// Sum each vector element over F, returning a new vector (dcrd
/// `AddVectors`).  When peers are honest (DC-mix pads sum to zero)
/// this creates the unpadded vector of message power sums.
pub fn add_vectors(vs: &[Vec<FieldInt>]) -> Vec<FieldInt> {
    let mut sums = Vec::with_capacity(vs.len());
    for i in 0..vs.len() {
        let mut sum = FieldInt::ZERO;
        for v in vs {
            sum = sum.add(&v[i]);
        }
        sums.push(sum);
    }
    sums
}

/// Calculate a{0}..a{n} for the polynomial
/// `g(x) = a{0} + a{1}x + ... + a{n}x**n (mod F)` whose roots are the
/// set of recovered messages (dcrd `Coefficients`).  The returned
/// slice is one element larger than the slice of partial sums.
pub fn coefficients(s: &[FieldInt]) -> Vec<FieldInt> {
    let n = s.len() + 1;
    let mut a = vec![FieldInt::ZERO; n];
    a[n - 1] = FieldInt(F - 1); // a{n} = -1 (mod F)
    for i in 0..n - 1 {
        let mut acc = FieldInt::ZERO;
        for j in 0..=i {
            acc = acc.add(&a[n - 1 - i + j].mul(&s[j]));
        }
        let xinv = FieldInt::from_u64(i as u64 + 1).inv().neg();
        a[n - 2 - i] = acc.mul(&xinv);
    }
    a
}

/// Check that the message m is a root of the polynomial with
/// coefficients a (mod F) without solving for every root (dcrd
/// `IsRoot`).
pub fn is_root(m: &FieldInt, a: &[FieldInt]) -> bool {
    let mut sum = FieldInt::ZERO;
    for (i, coeff) in a.iter().enumerate() {
        let term = m.pow(i as u128).mul(coeff);
        sum = sum.add(&term);
    }
    sum.is_zero()
}

/// The vector of DC-net pads from shared secrets with each mix
/// participant (dcrd `DCMixPads`).
pub fn dc_mix_pads(kp: &[MixVect], my: u32) -> Vect {
    let mut pads = vec![[0u8; MSIZE]; kp.len()];
    for (i, v) in kp.iter().enumerate() {
        if i as u32 == my {
            continue;
        }
        let src = pads.clone();
        vec_xor(&mut pads, &src, v);
    }
    pads
}

/// The DC-net vector of message m xor'd into m's reserved anonymous
/// slot position of the DC-net pads (dcrd `DCMix`).  Panics if the
/// message is not [`MSIZE`] bytes.
pub fn dc_mix(pads: &Vect, m: &[u8], slot: u32) -> Vect {
    assert_eq!(m.len(), MSIZE, "m is not len Msize");

    let mut dcmix = pads.clone();
    let slotm = &mut dcmix[slot as usize];
    for (i, byte) in m.iter().enumerate() {
        slotm[i] ^= byte;
    }
    dcmix
}
