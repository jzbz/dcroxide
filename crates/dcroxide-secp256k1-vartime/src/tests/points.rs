// SPDX-License-Identifier: ISC
//! Point helpers for the group, loop and GLV tests: conversions between
//! the crate's types and k256's, random points by a k256 random walk,
//! Jacobian forms at chosen magnitudes, and an affine reference over the
//! schoolbook mod-p words of `tests/mod.rs` (chord and tangent with a
//! Fermat inverse), for the small-order curves where k256 cannot help.

use dcroxide_testutil::SplitMix64;
use k256::elliptic_curve::group::CurveAffine;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::{AffinePoint, ProjectivePoint};

use super::*;
use crate::group::{Ge, Gej};
use crate::scalar::Scalar;

/// The crate's scalar as k256's.
pub(crate) fn to_k(s: &Scalar) -> k256::Scalar {
    Option::from(k256::Scalar::from_repr(s.to_be_bytes().into())).expect("below N")
}

/// A small signed integer as a scalar mod N.
pub(crate) fn sc_i64(v: i64) -> Scalar {
    let s = Scalar::reduce_be_bytes(&words_to_be(&[v.unsigned_abs(), 0, 0, 0]));
    if v < 0 { -s } else { s }
}

/// 2^128 as a scalar.
pub(crate) fn pow2_128() -> Scalar {
    Scalar::from_be_bytes(&words_to_be(&[0, 0, 1, 0])).expect("below N")
}

/// A random scalar: uniform, or structured every fourth call.
pub(crate) fn rand_scalar(r: &mut SplitMix64) -> Scalar {
    let w = if r.below(4) == 0 {
        words_structured(r)
    } else {
        words(r)
    };
    Scalar::reduce_be_bytes(&words_to_be(&w))
}

/// A field element from canonical big-endian bytes.
pub(crate) fn fe_be(b: &[u8; 32]) -> Fe {
    Fe::set_b32_limit(b).expect("below p")
}

/// The same value at magnitude m (2..=32), with limbs near the bound: a
/// negation of the negation.
pub(crate) fn inflate(f: &Fe, m: u8) -> Fe {
    assert!((2..=32).contains(&m));
    norm(&norm(f).negate(1)).negate(m - 1)
}

/// A k256 affine point (not the identity) as the crate's, normalized.
pub(crate) fn ge_from_k(p: &AffinePoint) -> Ge {
    Ge::set_xy(&fe_be(&p.x().into()), &fe_be(&p.y().into()))
}

/// A k256 projective point as the crate's affine one, infinity included.
pub(crate) fn ge_from_kp(p: &ProjectivePoint) -> Ge {
    let a = p.to_affine();
    if bool::from(a.is_identity()) {
        Ge::INFINITY
    } else {
        ge_from_k(&a)
    }
}

/// The crate's affine point (on the curve, not infinity) as k256's.
pub(crate) fn ge_to_k(g: &Ge) -> AffinePoint {
    assert!(!g.infinity);
    let (x, y) = (fe_bytes(&g.x), fe_bytes(&g.y));
    Option::from(AffinePoint::from_coordinates(&x.into(), &y.into())).expect("on the curve")
}

/// The crate's affine point as a k256 projective one, infinity included.
pub(crate) fn ge_to_kp(g: &Ge) -> ProjectivePoint {
    if g.infinity {
        ProjectivePoint::IDENTITY
    } else {
        ProjectivePoint::from(ge_to_k(g))
    }
}

/// A k256 point's affine coordinates, `None` for the identity.
pub(crate) fn kp_bytes(p: &ProjectivePoint) -> Option<Bytes2> {
    let a = p.to_affine();
    if bool::from(a.is_identity()) {
        None
    } else {
        Some((a.x().into(), a.y().into()))
    }
}

/// A Jacobian point's affine coordinates through `set_gej_var`, `None` at
/// infinity, checking that `set_gej_var` normalized both coordinates limb
/// for limb, in every profile.
pub(crate) fn gej_bytes(p: &Gej) -> Option<Bytes2> {
    let g = Ge::set_gej_var(p).expect("inversion cap");
    if g.infinity {
        assert!(p.infinity);
        return None;
    }
    assert_eq!(
        g.x.raw().n,
        norm(&g.x).raw().n,
        "set_gej_var x not normalized"
    );
    assert_eq!(
        g.y.raw().n,
        norm(&g.y).raw().n,
        "set_gej_var y not normalized"
    );
    Some((g.x.get_b32(), g.y.get_b32()))
}

/// An affine point's coordinates, `None` at infinity.
pub(crate) fn ge_bytes(g: &Ge) -> Option<Bytes2> {
    if g.infinity {
        None
    } else {
        Some((fe_bytes(&g.x), fe_bytes(&g.y)))
    }
}

/// A random nonzero field element, normalized.
pub(crate) fn rand_fe_nz(r: &mut SplitMix64) -> Fe {
    loop {
        let w = words(r);
        if !ge4(&w, &P) && w != [0; 4] {
            return fe_w(&w);
        }
    }
}

/// The Jacobian form of an affine point with Z = z, X and Y inflated to
/// magnitudes mx and my (1 leaves the products as they are).
pub(crate) fn to_jac(g: &Ge, z: &Fe, mx: u8, my: u8) -> Gej {
    if g.infinity {
        return Gej::INFINITY;
    }
    let z2 = z.sqr();
    let z3 = z2.mul(z);
    let mut x = g.x.mul(&z2);
    let mut y = g.y.mul(&z3);
    if mx > 1 {
        x = inflate(&x, mx);
    }
    if my > 1 {
        y = inflate(&y, my);
    }
    let r = Gej {
        x,
        y,
        z: *z,
        infinity: false,
    };
    r.verify();
    r
}

/// A k256 random walk over the curve: each step adds one of 64 random
/// points, independently of the code under test.
pub(crate) struct Walk {
    pool: Vec<ProjectivePoint>,
    cur: ProjectivePoint,
}

impl Walk {
    pub(crate) fn new(r: &mut SplitMix64) -> Self {
        let pool = (0..64)
            .map(|_| ProjectivePoint::GENERATOR * to_k(&rand_scalar(r)))
            .collect();
        let cur = ProjectivePoint::GENERATOR * to_k(&rand_scalar(r));
        Self { pool, cur }
    }

    /// The next point, skipping the identity should the walk meet it.
    pub(crate) fn next(&mut self, r: &mut SplitMix64) -> AffinePoint {
        loop {
            self.cur += self.pool[r.below(64) as usize];
            let a = self.cur.to_affine();
            if !bool::from(a.is_identity()) {
                return a;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The affine reference.

/// p - 2, little-endian.
const P_MINUS_2: [u64; 4] = [0xFFFF_FFFE_FFFF_FC2D, u64::MAX, u64::MAX, u64::MAX];

/// a^-1 mod p by Fermat, on the schoolbook words.
pub(crate) fn inv_p(a: &[u64; 4]) -> [u64; 4] {
    let mut r = [1, 0, 0, 0];
    for i in (0..256).rev() {
        r = mul_p(&r, &r);
        if (P_MINUS_2[i / 64] >> (i % 64)) & 1 == 1 {
            r = mul_p(&r, a);
        }
    }
    r
}

/// An affine point of the reference; `None` is infinity.
pub(crate) type RefPt = Option<([u64; 4], [u64; 4])>;

/// Affine addition on y^2 = x^3 + b, any b: the chord and tangent
/// formulas do not use it.
pub(crate) fn ref_add(p: &RefPt, q: &RefPt) -> RefPt {
    let (Some((x1, y1)), Some((x2, y2))) = (p, q) else {
        return if p.is_none() { *q } else { *p };
    };
    let lam = if x1 == x2 {
        if add_p(y1, y2) == [0; 4] {
            return None;
        }
        // (3x^2) / (2y)
        let x1s = mul_p(x1, x1);
        let num = add_p(&add_p(&x1s, &x1s), &x1s);
        mul_p(&num, &inv_p(&add_p(y1, y1)))
    } else {
        mul_p(&sub_p(y2, y1), &inv_p(&sub_p(x2, x1)))
    };
    let x3 = sub_p(&sub_p(&mul_p(&lam, &lam), x1), x2);
    let y3 = sub_p(&mul_p(&lam, &sub_p(x1, &x3)), y1);
    Some((x3, y3))
}

/// The reference point of the crate's affine point.
pub(crate) fn ref_of(g: &Ge) -> RefPt {
    if g.infinity {
        None
    } else {
        Some((fe_val(&g.x), fe_val(&g.y)))
    }
}

/// The crate's affine point of a reference point.
pub(crate) fn ge_of_ref(p: &RefPt) -> Ge {
    match p {
        None => Ge::INFINITY,
        Some((x, y)) => Ge::set_xy(&fe_w(x), &fe_w(y)),
    }
}

/// Whether a Jacobian point equals a reference point, by cross
/// multiplication (X = x Z^2, Y = y Z^3, or both at infinity by the flag):
/// no inversion, so the exhaustive tests can afford it.
pub(crate) fn ref_eq_j(g: &Gej, want: &RefPt) -> bool {
    match want {
        None => g.infinity,
        Some((x, y)) => {
            if g.infinity {
                return false;
            }
            let z = fe_val(&g.z);
            let z2 = mul_p(&z, &z);
            let z3 = mul_p(&z2, &z);
            fe_val(&g.x) == mul_p(x, &z2) && fe_val(&g.y) == mul_p(y, &z3)
        }
    }
}
