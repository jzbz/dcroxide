// SPDX-License-Identifier: ISC
//! Helpers shared by the dcrd-judged branch tests of the vartime seam
//! (`vartime_ecdsa_branches.rs`, `vartime_recovery_schnorr_branches.rs`):
//! big-endian byte arithmetic, k256 scalars and points, the collision
//! grid's base points, the points with a tiny y, the volume switch, and
//! the committed vector files' checks.

#![allow(dead_code, reason = "each test file uses part of it")]
#![allow(
    clippy::arithmetic_side_effects,
    reason = "k256 scalar and field operators, which are modular, and byte \
              offsets within 32-byte arrays"
)]

use dcroxide_testutil::SplitMix64;
use k256::elliptic_curve::hazmat::FieldArithmetic;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::point::DecompressPoint;
use k256::elliptic_curve::subtle::Choice;
use k256::elliptic_curve::{Field, PrimeField};
use k256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar};

/// k256's field element.
pub type Fe = <k256::Secp256k1 as FieldArithmetic>::FieldElement;

/// P - N, big-endian.
pub const P_MINUS_N: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x45, 0x51, 0x23, 0x19, 0x50, 0xb7, 0x5f, 0xc4, 0x40, 0x2d, 0xa1, 0x72, 0x2f, 0xc9, 0xba, 0xee,
];

/// lambda, the endomorphism's scalar, big-endian.
pub const LAMBDA: [u8; 32] = [
    0x53, 0x63, 0xad, 0x4c, 0xc0, 0x5c, 0x30, 0xe0, 0xa5, 0x26, 0x1c, 0x02, 0x88, 0x12, 0x64, 0x5a,
    0x12, 0x2e, 0x22, 0xea, 0x20, 0x81, 0x66, 0x78, 0xdf, 0x02, 0x96, 0x7c, 0x1b, 0x23, 0xbd, 0x72,
];

/// a + b, big-endian, with no carry out (the callers' sums stay below P).
pub fn add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let s = u16::from(a[i]) + u16::from(b[i]) + carry;
        out[i] = s as u8;
        carry = s >> 8;
    }
    assert_eq!(carry, 0);
    out
}

/// a - b, big-endian, for a >= b.
pub fn sub(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = i16::from(a[i]) - i16::from(b[i]) - borrow;
        out[i] = d.rem_euclid(256) as u8;
        borrow = i16::from(d < 0);
    }
    assert_eq!(borrow, 0);
    out
}

/// A small value, big-endian.
pub fn small(v: u64) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[24..].copy_from_slice(&v.to_be_bytes());
    b
}

/// A scalar from big-endian bytes below N.
pub fn scalar(b: &[u8; 32]) -> Scalar {
    Option::from(Scalar::from_repr((*b).into())).expect("below N")
}

/// A small signed integer as a scalar.
pub fn sc_i64(v: i64) -> Scalar {
    let s = Scalar::from(v.unsigned_abs());
    if v < 0 { -s } else { s }
}

/// A random nonzero scalar.
pub fn rand_scalar(rng: &mut SplitMix64) -> Scalar {
    loop {
        let mut b = [0u8; 32];
        rng.fill(&mut b);
        let s = <Scalar as Reduce<FieldBytes>>::reduce(&b.into());
        if !bool::from(s.is_zero()) {
            return s;
        }
    }
}

/// The collision grid's base points: G, 2G, 3G, lambda G, lambda^2 G,
/// 2^128 G and lambda 2^128 G, by name; the grids take each and its
/// negation.
pub fn grid_bases() -> [(&'static str, ProjectivePoint); 7] {
    let g = ProjectivePoint::GENERATOR;
    let lam = scalar(&LAMBDA);
    let t = pow2_128();
    [
        ("G", g),
        ("2G", g.double()),
        ("3G", g * Scalar::from(3u64)),
        ("lG", g * lam),
        ("l^2G", g * (lam * lam)),
        ("2^128G", g * t),
        ("l2^128G", g * (lam * t)),
    ]
}

/// 2^128 as a scalar.
pub fn pow2_128() -> Scalar {
    let mut two128 = [0u8; 32];
    two128[15] = 1;
    scalar(&two128)
}

/// The point with x and the given oddness, by k256's decompression.
pub fn point_at(x: &[u8; 32], odd: bool) -> Option<AffinePoint> {
    Option::from(AffinePoint::decompress(
        &(*x).into(),
        Choice::from(u8::from(odd)),
    ))
}

/// The x of every point whose y is below 200, on k256's field: y^2 - 7
/// must be a cube, one cube root is (y^2 - 7)^((P+2)/9) since P = 7 mod 9,
/// and the others are it times beta and beta^2.
pub fn tiny_y_xs() -> Vec<[u8; 32]> {
    // (P + 2) / 9, little-endian words.
    const CUBE_ROOT_EXP: [u64; 4] = [
        0x1c71_c71c_5555_54e9,
        0x71c7_1c71_c71c_71c7,
        0xc71c_71c7_1c71_c71c,
        0x1c71_c71c_71c7_1c71,
    ];
    const BETA: [u8; 32] = [
        0x7a, 0xe9, 0x6a, 0x2b, 0x65, 0x7c, 0x07, 0x10, 0x6e, 0x64, 0x47, 0x9e, 0xac, 0x34, 0x34,
        0xe9, 0x9c, 0xf0, 0x49, 0x75, 0x12, 0xf5, 0x89, 0x95, 0xc1, 0x39, 0x6c, 0x28, 0x71, 0x95,
        0x01, 0xee,
    ];
    let beta: Fe = Option::from(Fe::from_repr(BETA.into())).expect("beta below P");
    let seven = Fe::from(7u64);
    let mut xs = Vec::new();
    for y in 1..200u64 {
        let c = (Fe::from(y).square() - seven).normalize();
        let x = c.pow_vartime(CUBE_ROOT_EXP);
        if bool::from((x.square() * x - c).normalize().is_zero()) {
            for x in [x, x * beta, x * beta.square()] {
                xs.push(x.normalize().to_repr().into());
            }
        }
    }
    assert_eq!(xs.len(), 183, "points with y < 200");
    xs
}

/// Whether the full sets run: release without debug assertions, or the
/// 10^6 volume as CI's soak-asserts run sets it.
pub fn full() -> bool {
    !cfg!(debug_assertions)
        || std::env::var("DCROXIDE_VARTIME_CASES")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .is_some_and(|n| n >= 1_000_000)
}

/// A committed file's data lines, split on `|`: comments and blank lines
/// skipped.
pub fn data_lines(text: &str) -> impl Iterator<Item = (&str, Vec<&str>)> {
    text.lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| (l, l.split('|').collect()))
}

/// The committed file must equal its regenerated text byte for byte.  On
/// a difference, with the environment variable `env` naming a path, the
/// regenerated text is written there, never into the source tree, and
/// the test still fails.
pub fn require_regenerated(text: &str, committed: &str, env: &str, file: &str) {
    if text != committed {
        if let Ok(path) = std::env::var(env) {
            std::fs::write(&path, text).expect("write the regenerated vectors");
            println!("wrote {path}");
        }
        panic!("{file} differs from its construction");
    }
}
