// SPDX-License-Identifier: ISC AND MIT
//
// The small-order curves' generators, curve constants and lambdas (SMALL
// below) are copied from libsecp256k1 src/group_impl.h:17-35 and :51-67
// (Copyright (c) 2013, 2014 Pieter Wuille) and src/scalar_impl.h:50-55
// (Copyright (c) 2014 Pieter Wuille), as vendored by secp256k1-sys
// 0.14.1.  MIT; see NOTICE.
//
//! Group tests: every formula against k256's complete formulas, with
//! random, equal, opposite and lambda-related operands, infinity on either
//! side and the largest magnitudes their contracts allow; dcrd's Jacobian
//! addition and doubling vectors; the formulas on limbs at the extremes of
//! their magnitudes against the reference; the inversion-free x check; and
//! on libsecp256k1's small test curves of orders 7, 13 and 199, every pair
//! of points through every formula, the key table, and the production
//! Straus loop for every key and every pair of scalars, against index
//! arithmetic.

use std::sync::atomic::{AtomicU64, Ordering};

use dcroxide_testutil::SplitMix64;
use k256::ProjectivePoint;

use super::branches::{self, BRANCH_NAMES, Counts, N_BRANCH, N_SITE, SITE_NAMES, Site};
use super::points::*;
use super::*;
use crate::ecmult::{Digits, TABLE_SIZE_A, WINDOW_A, odd_multiples_table, strauss_core};
use crate::field::{BETA, Fe};
use crate::group::{G, Ge, Gej};
use crate::wnaf::try_wnaf;

/// Whether the heavy tests run in full: at the release and soak-asserts
/// volume of 10^6 cases.
fn full() -> bool {
    cases() >= 1_000_000
}

/// The rzr contract: out.z = a.z * rzr, when neither is infinity.
fn check_rzr(a: &Gej, out: &Gej, rzr: &Fe) {
    if a.infinity || out.infinity {
        return;
    }
    assert_eq!(
        fe_bytes(&a.z.mul(rzr)),
        fe_bytes(&out.z),
        "rzr != out.z / a.z"
    );
}

/// Every formula against k256 on random points from a k256 walk: the
/// second operand random, equal, opposite, lambda times the first (x
/// differs, y equal), its negation, or infinity, and the first at
/// infinity; Jacobian X and Y at magnitude 4 and affine x and y at 4 and 3
/// on two cases in three; `add_zinv_var`'s addend scaled by a random
/// 1/zinv; the rzr contract wherever a formula gives one.
#[test]
fn formulas_vs_k256() {
    let mut r = SplitMix64(0x6772_6f75_7031);
    let mut walk = Walk::new(&mut r);
    let n = cases() / 10;
    let mut shapes = [0u64; 8];
    for i in 0..n {
        let p = ge_from_k(&walk.next(&mut r));
        let shape = (i % 8) as usize;
        shapes[shape] += 1;
        let q = match shape {
            0 | 1 => ge_from_k(&walk.next(&mut r)),
            2 => p,
            3 => p.neg(),
            4 => {
                let mut l = p.mul_lambda();
                l.x.normalize();
                l
            }
            5 => {
                let mut l = p.mul_lambda().neg();
                l.x.normalize();
                l.y.normalize();
                l
            }
            _ => Ge::INFINITY,
        };
        let p = if shape == 7 { Ge::INFINITY } else { p };
        let (pk, qk) = (ge_to_kp(&p), ge_to_kp(&q));

        let za = rand_fe_nz(&mut r);
        let zb = rand_fe_nz(&mut r);
        let (mx, my) = if i % 3 == 0 { (1, 1) } else { (4, 4) };
        let aj = to_jac(&p, &za, mx, my);
        let bj = to_jac(&q, &zb, mx, my);
        let mut bge = q;
        if !q.infinity && i % 3 != 0 {
            bge.x = inflate(&q.x, 4);
            bge.y = inflate(&q.y, 3);
        }

        let mut rzr = fe_w(&[7, 0, 0, 0]);
        let d = aj.double_var(Some(&mut rzr));
        assert_eq!(gej_bytes(&d), kp_bytes(&pk.double()), "double case {i}");
        check_rzr(&aj, &d, &rzr);
        assert_eq!(gej_bytes(&aj.double_var(None)), gej_bytes(&d));
        if !aj.infinity {
            assert_eq!(gej_bytes(&aj.double()), gej_bytes(&d));
        }

        let want = kp_bytes(&(pk + qk));

        let mut rzr = fe_w(&[7, 0, 0, 0]);
        let s = if aj.infinity {
            aj.add_var(&bj, None)
        } else {
            aj.add_var(&bj, Some(&mut rzr))
        };
        assert_eq!(gej_bytes(&s), want, "add_var case {i} shape {shape}");
        check_rzr(&aj, &s, &rzr);

        let mut rzr = fe_w(&[7, 0, 0, 0]);
        let s = if aj.infinity {
            aj.add_ge_var(&bge, None)
        } else {
            aj.add_ge_var(&bge, Some(&mut rzr))
        };
        assert_eq!(gej_bytes(&s), want, "add_ge_var case {i} shape {shape}");
        check_rzr(&aj, &s, &rzr);
        if shape == 3 {
            assert!(
                s.infinity && rzr.normalizes_to_zero_var(),
                "opposite: rzr = 0"
            );
        }

        // b = (q.x / zi^2, q.y / zi^3) with Z = 1/zi represents q exactly.
        let zi = rand_fe_nz(&mut r);
        let mut bz = q;
        if !q.infinity {
            let zinv = zi.inv_var().expect("cap");
            let zinv2 = zinv.sqr();
            bz.x = q.x.mul(&zinv2);
            bz.y = q.y.mul(&zinv2.mul(&zinv));
        }
        let s = aj.add_zinv_var(&bz, &zi);
        assert_eq!(gej_bytes(&s), want, "add_zinv_var case {i} shape {shape}");
    }
    assert!(shapes.iter().all(|&c| c > 0));
}

/// dcrd's `TestAddJacobian` and `TestDoubleJacobian` vectors, among them
/// btcd issue #709's doubling, compared as affine points: dcrd's Jacobian
/// outputs come from other formulas, so only the point is common.
#[test]
fn dcrd_jacobian_vectors() {
    use super::dcrd_vectors::{ADD_JACOBIAN, DOUBLE_JACOBIAN};
    fn hex_fe(h: &str) -> Fe {
        fe_be(&hex32(&format!("{h:0>64}")))
    }
    fn jac(x: &str, y: &str, z: &str) -> Gej {
        let (x, y, z) = (hex_fe(x), hex_fe(y), hex_fe(z));
        if z.normalizes_to_zero_var() {
            return Gej::INFINITY;
        }
        Gej {
            x,
            y,
            z,
            infinity: false,
        }
    }
    for v in ADD_JACOBIAN {
        let a = jac(v[1], v[2], v[3]);
        let b = jac(v[4], v[5], v[6]);
        let want = jac(v[7], v[8], v[9]);
        assert_eq!(
            gej_bytes(&a.add_var(&b, None)),
            gej_bytes(&want),
            "{}",
            v[0]
        );
        if !b.infinity && b.z.equal(&Fe::ONE) {
            let bg = Ge::set_xy(&b.x, &b.y);
            assert_eq!(
                gej_bytes(&a.add_ge_var(&bg, None)),
                gej_bytes(&want),
                "{} (ge)",
                v[0]
            );
            assert_eq!(
                gej_bytes(&a.add_zinv_var(&bg, &Fe::ONE)),
                gej_bytes(&want),
                "{} (zinv)",
                v[0]
            );
        }
    }
    for v in DOUBLE_JACOBIAN {
        let a = jac(v[1], v[2], v[3]);
        let want = jac(v[4], v[5], v[6]);
        assert_eq!(gej_bytes(&a.double_var(None)), gej_bytes(&want), "{}", v[0]);
    }
    // btcd issue #709's vector, by its name in dcrd.
    assert!(
        DOUBLE_JACOBIAN
            .iter()
            .any(|v| v[0] == "carry to bit 256 during normalize")
    );
}

/// `set_gej_var` normalizes both coordinates limb for limb, in every
/// profile; `eq_x_var` agrees with the affine x and refuses x + 1.
#[test]
fn set_gej_var_normalizes_and_eq_x() {
    let mut r = SplitMix64(0x6e6f_726d);
    let mut walk = Walk::new(&mut r);
    for _ in 0..cases() / 20 {
        let p = ge_from_k(&walk.next(&mut r));
        let j = to_jac(&p, &rand_fe_nz(&mut r), 4, 4);
        let g = Ge::set_gej_var(&j).expect("cap");
        assert_eq!(g.x.raw().n, norm(&g.x).raw().n);
        assert_eq!(g.y.raw().n, norm(&g.y).raw().n);
        #[cfg(debug_assertions)]
        assert!(g.x.is_normalized_claim() && g.y.is_normalized_claim());
        assert_eq!(ge_bytes(&g), ge_bytes(&p));
        assert!(j.eq_x_var(&p.x));
        let mut x1 = p.x;
        x1.add_int(1);
        x1.normalize();
        assert!(!j.eq_x_var(&x1));
    }
    assert!(Ge::set_gej_var(&Gej::INFINITY).expect("cap").infinity);
}

/// The generator constant is k256's, and on the curve.
#[test]
fn generator_matches_k256() {
    assert_eq!(ge_bytes(&G), kp_bytes(&ProjectivePoint::GENERATOR));
    assert!(G.is_valid_var());
}

// ---------------------------------------------------------------------------
// The formulas on extreme limbs.

const M52: u64 = 0xF_FFFF_FFFF_FFFF;
const M48: u64 = 0xFFFF_FFFF_FFFF;

/// Schoolbook words.
type W = [u64; 4];

/// A field element at magnitude m, not normalized, each limb picked from
/// its maximum, zero, its maximum less one, or random up to its maximum.
fn extreme(r: &mut SplitMix64, m: u8) -> Fe {
    let k = 2 * u64::from(m);
    let lim = [M52 * k, M52 * k, M52 * k, M52 * k, M48 * k];
    let mode = r.below(5);
    let mut n = [0u64; 5];
    for i in 0..5 {
        let pick = if mode == 4 { r.below(4) } else { mode };
        n[i] = match pick {
            0 => lim[i],
            1 => 0,
            2 => lim[i] - 1,
            _ => r.next_u64() % (lim[i] + 1),
        };
    }
    Fe::from_limbs(n, m, false)
}

/// The generic tail the three additions share, on the reference.
fn tail(u1: &W, s1: &W, h: &W, i: &W) -> (W, W) {
    let h2 = neg_p(&mul_p(h, h));
    let h3 = mul_p(&h2, h);
    let t = mul_p(u1, &h2);
    let rx = add_p(&add_p(&add_p(&mul_p(i, i), &h3), &t), &t);
    let ry = add_p(&mul_p(&add_p(&t, &rx), i), &mul_p(&h3, s1));
    (rx, ry)
}

/// The Jacobian point's coordinates equal the reference's, value for
/// value.
fn check_j(name: &str, g: &Gej, x: &W, y: &W, z: &W) {
    assert!(!g.infinity, "{name}: infinity");
    assert_eq!(fe_val(&g.x), *x, "{name}: X");
    assert_eq!(fe_val(&g.y), *y, "{name}: Y");
    assert_eq!(fe_val(&g.z), *z, "{name}: Z");
}

/// Every formula's generic path on operands whose limbs sit at the
/// extremes their magnitudes allow, against the same formulas on the
/// reference.  The values are not curve points (the formulas never use
/// b): the limbs, not the values, are what is adversarial here.  Each
/// output is fed back in, so its magnitudes must be legal inputs again.
#[test]
fn formulas_on_extreme_limbs() {
    let n = (cases() / 10).max(2_000);
    let mut r = SplitMix64(0x7265_7669_6577_2d63);
    let inv2 = inv_p(&[2, 0, 0, 0]);
    let three = [3u64, 0, 0, 0];
    let mut generic = [0u64; 3];
    for _ in 0..n {
        let a = Gej {
            x: extreme(&mut r, 4),
            y: extreme(&mut r, 4),
            z: extreme(&mut r, 1),
            infinity: false,
        };
        let b = Ge {
            x: extreme(&mut r, 4),
            y: extreme(&mut r, 3),
            infinity: false,
        };
        let bj = Gej {
            x: extreme(&mut r, 4),
            y: extreme(&mut r, 4),
            z: extreme(&mut r, 1),
            infinity: false,
        };
        let bzinv = extreme(&mut r, 1);
        let (ax, ay, az) = (fe_val(&a.x), fe_val(&a.y), fe_val(&a.z));
        let (bx, by) = (fe_val(&b.x), fe_val(&b.y));

        let mut rzr = Fe::ZERO;
        let d = a.double_var(Some(&mut rzr));
        let l = mul_p(&mul_p(&three, &mul_p(&ax, &ax)), &inv2);
        let s = mul_p(&ay, &ay);
        let t = neg_p(&mul_p(&ax, &s));
        let x3 = add_p(&add_p(&mul_p(&l, &l), &t), &t);
        let y3 = neg_p(&add_p(&mul_p(&l, &add_p(&x3, &t)), &mul_p(&s, &s)));
        check_j("double", &d, &x3, &y3, &mul_p(&ay, &az));
        assert_eq!(fe_val(&rzr), ay);
        let _ = d.double_var(None);

        let z12 = mul_p(&az, &az);
        let h = sub_p(&mul_p(&bx, &z12), &ax);
        let i = sub_p(&ay, &mul_p(&mul_p(&by, &z12), &az));
        if h != [0; 4] {
            let mut rzr = Fe::ZERO;
            let g = a.add_ge_var(&b, Some(&mut rzr));
            let (rx, ry) = tail(&ax, &ay, &h, &i);
            check_j("add_ge_var", &g, &rx, &ry, &mul_p(&az, &h));
            assert_eq!(fe_val(&rzr), h);
            let _ = g.double_var(None).add_ge_var(&b, None);
            generic[0] += 1;
        }

        let azz = mul_p(&az, &fe_val(&bzinv));
        let z12 = mul_p(&azz, &azz);
        let h = sub_p(&mul_p(&bx, &z12), &ax);
        let i = sub_p(&ay, &mul_p(&mul_p(&by, &z12), &azz));
        if h != [0; 4] {
            let g = a.add_zinv_var(&b, &bzinv);
            let (rx, ry) = tail(&ax, &ay, &h, &i);
            check_j("add_zinv_var", &g, &rx, &ry, &mul_p(&az, &h));
            let _ = g.add_zinv_var(&b, &bzinv);
            generic[1] += 1;
        }

        let (bxj, byj, bzj) = (fe_val(&bj.x), fe_val(&bj.y), fe_val(&bj.z));
        let z22 = mul_p(&bzj, &bzj);
        let z12 = mul_p(&az, &az);
        let u1 = mul_p(&ax, &z22);
        let s1 = mul_p(&mul_p(&ay, &z22), &bzj);
        let h = sub_p(&mul_p(&bxj, &z12), &u1);
        let i = sub_p(&s1, &mul_p(&mul_p(&byj, &z12), &az));
        if h != [0; 4] {
            let mut rzr = Fe::ZERO;
            let g = a.add_var(&bj, Some(&mut rzr));
            let t = mul_p(&h, &bzj);
            let (rx, ry) = tail(&u1, &s1, &h, &i);
            check_j("add_var", &g, &rx, &ry, &mul_p(&az, &t));
            assert_eq!(fe_val(&rzr), t);
            generic[2] += 1;
        }

        assert_eq!(fe_val(&b.neg().y), neg_p(&by));
        assert_eq!(fe_val(&b.mul_lambda().x), mul_p(&bx, &fe_val(&BETA)));
        let zi = fe_val(&bzinv);
        let gz = b.set_ge_zinv(&bzinv);
        assert_eq!(fe_val(&gz.x), mul_p(&bx, &mul_p(&zi, &zi)));
        assert_eq!(fe_val(&gz.y), mul_p(&by, &mul_p(&zi, &mul_p(&zi, &zi))));
        assert_eq!(fe_val(&a.neg().y), neg_p(&ay));
    }
    assert!(generic.iter().all(|&g| g > n / 2), "{generic:?}");
}

/// `eq_x_var` with X at magnitudes 2 to 4, limbs near the bound (an
/// inflated zero among them), and x in [N, p), tiny, p - 1 or 0: true for
/// x, false for x + 1 and for x - N.  Through the public x check too, with
/// the r and r + N of ECDSA's steps 8 and 10.
#[test]
fn eq_x_on_inflated_x() {
    let n = (cases() / 10).max(2_000);
    let mut r = SplitMix64(0x6571_785f_696e_666c);
    let pm1 = sub4(&P, &[1, 0, 0, 0]);
    let pmn = sub4(&P, &NORD);
    for k in 0..n {
        let x: W = match k % 6 {
            0 => NORD,
            1 => pm1,
            2 => {
                let w = [r.next_u64(), r.next_u64() & 1, 0, 0];
                let w = if ge4(&w, &pmn) { [0; 4] } else { w };
                let mut s = [0u64; 4];
                let mut c = 0u128;
                for i in 0..4 {
                    let t = u128::from(NORD[i]) + u128::from(w[i]) + c;
                    s[i] = t as u64;
                    c = t >> 64;
                }
                s
            }
            3 => [r.below(1000), 0, 0, 0],
            4 => [0; 4],
            _ => words_below_p(&mut r),
        };
        let z = rand_fe_nz(&mut r);
        let fx = fe_w(&x);
        let mag = 2 + (k % 3) as u8;
        let g = Gej {
            x: inflate(&fx.mul(&z.sqr()), mag),
            y: rand_fe_nz(&mut r),
            z,
            infinity: false,
        };
        g.verify();
        assert!(
            g.eq_x_var(&fx),
            "eq_x_var(x) false, x = {x:x?}, magnitude {mag}"
        );
        let mut xp1 = x;
        xp1[0] = xp1[0].wrapping_add(1);
        if !ge4(&xp1, &P) && xp1[0] != 0 {
            assert!(!g.eq_x_var(&fe_w(&xp1)), "eq_x_var(x + 1) true");
        }
        if ge4(&x, &NORD) {
            let rr = sub4(&x, &NORD);
            assert!(!g.eq_x_var(&fe_w(&rr)), "eq_x_var(x - N) true");
            let pt = crate::Point::from_gej(g);
            assert!(pt.x_equals_var(&words_to_be(&x)));
            assert!(!pt.x_equals_var(&words_to_be(&rr)));
        }
    }
}

// ---------------------------------------------------------------------------
// libsecp256k1's small test curves: the same field, y^2 = x^3 + b.

/// A small curve: (order, b, generator x, generator y, lambda).
type SmallCurve = (u64, u64, [u32; 8], [u32; 8], u64);

/// The three small curves (group_impl.h:17-35 and :51-67,
/// scalar_impl.h:50-55).
const SMALL: [SmallCurve; 3] = [
    (
        7,
        6,
        [
            0x6662_5d13,
            0x317f_fe44,
            0x63d3_2cff,
            0x1ca0_2b9b,
            0xe5c6_d070,
            0x50b4_b05e,
            0x81cc_30db,
            0xf516_6f0a,
        ],
        [
            0x1e60_e897,
            0xa7c0_0c7c,
            0x2df5_3eb6,
            0x9827_4ff4,
            0x6425_2f42,
            0x8ca4_4e17,
            0x3b25_418c,
            0xff4a_b0cf,
        ],
        2,
    ),
    (
        13,
        2,
        [
            0xa248_2ff8,
            0x4bf3_4edf,
            0xa512_62fd,
            0xe579_21db,
            0xe0dd_2cb7,
            0xa591_4790,
            0xbc71_631f,
            0xc097_04fb,
        ],
        [
            0x9425_36cb,
            0xa3e4_9492,
            0x3a70_1cc3,
            0xee3e_443f,
            0xdf18_2aa9,
            0x15b8_aa6a,
            0x166d_3b19,
            0xba84_b045,
        ],
        9,
    ),
    (
        199,
        4,
        [
            0x7fb0_7b5c,
            0xd07c_3bda,
            0x5539_02e2,
            0x7a87_ea2c,
            0x3510_8a7f,
            0x051f_41e5,
            0xb76a_bad5,
            0x1f27_03ad,
        ],
        [
            0x0a25_1539,
            0x5b4c_4438,
            0x952a_634f,
            0xac10_dd4d,
            0x6d6f_4745,
            0x9899_0c27,
            0x3a4f_3116,
            0xd32f_f969,
        ],
        92,
    ),
];

/// The small curve's generator and its multiples k*G for k in 0..order
/// (index 0 is infinity), by the reference, after checking that the
/// generator is on its curve and that order*G is infinity.
fn small_multiples(idx: usize) -> (Ge, Vec<RefPt>) {
    let (order, b, gx, gy, _) = SMALL[idx];
    let g = Ge::set_xy(&Fe::from_be_u32(gx), &Fe::from_be_u32(gy));
    let (x, y) = (fe_val(&g.x), fe_val(&g.y));
    let rhs = add_p(&mul_p(&mul_p(&x, &x), &x), &[b, 0, 0, 0]);
    assert_eq!(
        mul_p(&y, &y),
        rhs,
        "order-{order} generator off y^2 = x^3 + {b}"
    );
    let gr = ref_of(&g);
    let mut m = vec![None, gr];
    for k in 2..=order {
        let next = ref_add(&m[(k - 1) as usize], &gr);
        m.push(next);
    }
    assert!(m[order as usize].is_none(), "order*G is not infinity");
    assert!(m[1..order as usize].iter().all(Option::is_some));
    m.truncate(order as usize);
    (g, m)
}

/// The field's cube root of unity that matches the small curve's lambda:
/// lambda*G = (beta*x, y).
fn small_beta(m: &[RefPt], lam: usize) -> Fe {
    let (gx, gy) = m[1].expect("G");
    let (lx, ly) = m[lam].expect("lambda*G");
    assert_eq!(gy, ly);
    let b1 = fe_val(&BETA);
    let b2 = mul_p(&b1, &b1);
    if mul_p(&gx, &b1) == lx {
        BETA
    } else {
        assert_eq!(mul_p(&gx, &b2), lx);
        fe_w(&b2)
    }
}

/// Every pair of points (infinity included) through `add_var`,
/// `add_ge_var` and `add_zinv_var`, and every point through `double_var`,
/// against index arithmetic, on the curves of orders 7, 13 and 199 (the
/// formulas never use b).  Jacobian operands have random Z and X, Y at
/// magnitude 4, affine ones x and y at 4 and 3.  Every branch of
/// `add_ge_var` must run.  Order 199 runs every 13th first operand below
/// the 10^6 volume.
#[test]
fn exhaustive_small_curve_formulas() {
    let mut r = SplitMix64(0x7431);
    for (idx, curve) in SMALL.iter().enumerate() {
        let order = curve.0 as usize;
        let (_, m) = small_multiples(idx);
        let pts: Vec<Ge> = m.iter().map(ge_of_ref).collect();
        let step = if order == 199 && !full() { 13 } else { 1 };
        let mut counts = [0u64; N_BRANCH];
        for i in (0..order).step_by(step) {
            let aj = to_jac(&pts[i], &rand_fe_nz(&mut r), 4, 4);
            assert!(
                ref_eq_j(&aj.double_var(None), &m[(2 * i) % order]),
                "order {order}: 2*{i}"
            );
            for j in 0..order {
                let want = m[(i + j) % order];
                let bj = to_jac(&pts[j], &rand_fe_nz(&mut r), 4, 4);
                assert!(
                    ref_eq_j(&aj.add_var(&bj, None), &want),
                    "{order}: add_var {i}+{j}"
                );
                let mut bge = pts[j];
                if !bge.infinity {
                    bge.x = inflate(&bge.x, 4);
                    bge.y = inflate(&bge.y, 3);
                }
                let s = aj.add_ge_var(&bge, None);
                counts[branches::last() as usize] += 1;
                assert!(ref_eq_j(&s, &want), "{order}: add_ge_var {i}+{j}");
                let zeta = rand_fe_nz(&mut r);
                let mut bz = pts[j];
                if !bz.infinity {
                    let zinv = zeta.inv_var().expect("cap");
                    let zinv2 = zinv.sqr();
                    bz.x = bz.x.mul(&zinv2);
                    bz.y = bz.y.mul(&zinv2.mul(&zinv));
                }
                assert!(
                    ref_eq_j(&aj.add_zinv_var(&bz, &zeta), &want),
                    "{order}: add_zinv_var {i}+{j}"
                );
            }
        }
        assert!(
            counts.iter().all(|&c| c > 0),
            "order {order}: a branch never ran: {counts:?}"
        );
    }
}

/// The key table and its shared Z on order 199, for every Q: entry i is
/// (2i+1)Q over Z, and the lambda entry, x times beta, is lambda(2i+1)Q.
/// Odd k enter with Z = 1, the production shape; even k with a random Z
/// and X, Y at magnitude 4, so that `a_i.z = a.z` (ecmult_impl.h:102)
/// matters.  On orders 7 and 13 the table's premise, no equal x, fails,
/// which the test states instead of running.
#[test]
fn odd_multiples_table_order199() {
    let (_, m) = small_multiples(2);
    let order = 199usize;
    let lam = SMALL[2].4 as usize;
    let beta = small_beta(&m, lam);
    let mut r = SplitMix64(0x6f_6464);
    for k in 1..order {
        let q = if k % 2 == 1 {
            Gej::set_ge(&ge_of_ref(&m[k]))
        } else {
            to_jac(&ge_of_ref(&m[k]), &rand_fe_nz(&mut r), 4, 4)
        };
        let mut pre = [Ge::INFINITY; TABLE_SIZE_A];
        let mut zr = [Fe::ZERO; TABLE_SIZE_A];
        let z = odd_multiples_table(&mut pre, &mut zr, &q);
        Ge::table_set_globalz(&mut pre, &zr);
        for (i, e) in pre.iter().enumerate() {
            let j = Gej {
                x: e.x,
                y: e.y,
                z,
                infinity: false,
            };
            assert!(
                ref_eq_j(&j, &m[(k * (2 * i + 1)) % order]),
                "Q={k}G entry {i}"
            );
            let jl = Gej {
                x: e.x.mul(&beta),
                y: e.y,
                z,
                infinity: false,
            };
            assert!(
                ref_eq_j(&jl, &m[(k * (2 * i + 1) * lam) % order]),
                "Q={k}G lambda entry {i}"
            );
        }
    }
    // Orders 7 and 13: some 2i-1 <= 15 is +-2 mod n, so the build would
    // meet an equal x.
    for n in [7i64, 13] {
        assert!((1..=8).any(|i| {
            let v = (2 * i - 1) % n;
            v == 2 || v == n - 2
        }));
    }
}

/// The production Straus loop, `strauss_core`, on the order-199 curve with
/// its lambda (92), its beta and window-8 tables of its G and 2^128 G from
/// the table generator, for each key Q: (1) every (na, ng) in 199^2 with
/// the shortest splits; (2) the box of splits a1, a2, g1, g2 in [-3, 3];
/// (3) random lifts of splits by multiples of 199, so the digit strings
/// span many positions.  Against index arithmetic.  Every special case of
/// every addition site must fire, and no table entry is infinity.  Below
/// the 10^6 volume, 8 keys and every 7th na.
#[test]
fn exhaustive_straus_order199() {
    const ORD: i64 = 199;
    let (g, m) = small_multiples(2);
    let lam = SMALL[2].4 as i64;
    let beta = small_beta(&m, lam as usize);
    let t = 155i64; // 2^128 mod 199
    assert_eq!((0..128).fold(1i64, |a, _| (a * 2) % ORD), t);
    let wg = 8u32;
    let pre_g = super::table_gen::compute_table(wg, &Gej::set_ge(&g));
    let pre_g_128 = super::table_gen::compute_table(wg, &Gej::set_ge(&ge_of_ref(&m[t as usize])));

    let md = |v: i64| v.rem_euclid(ORD);
    // The shortest split of v as a + b*mult mod 199 with |a|, |b| <= 15.
    let split = |v: i64, mult: i64| -> (i64, i64) {
        let mut best = (i64::MAX, 0, 0);
        for b in -15..=15i64 {
            for a in -15..=15i64 {
                if md(a + b * mult) == md(v) {
                    let n = a.abs().max(b.abs());
                    if n < best.0 {
                        best = (n, a, b);
                    }
                }
            }
        }
        (best.1, best.2)
    };
    let ms: Vec<Ge> = m.iter().map(ge_of_ref).collect();
    let run = |k: usize, a1: i64, a2: i64, g1: i64, g2: i64| {
        let mut d = Digits::new();
        let have_a = a1 != 0 || a2 != 0;
        if have_a {
            d.bits_na_1 = try_wnaf(&mut d.na_1, &sc_i64(a1), WINDOW_A).expect("guard");
            d.bits_na_lam = try_wnaf(&mut d.na_lam, &sc_i64(a2), WINDOW_A).expect("guard");
        }
        d.bits_ng_1 = try_wnaf(&mut d.ng_1, &sc_i64(g1), wg).expect("guard");
        d.bits_ng_128 = try_wnaf(&mut d.ng_128, &sc_i64(g2), wg).expect("guard");
        let q = Gej::set_ge(&ms[k]);
        let out = strauss_core(have_a.then_some(&q), &d, &pre_g, &pre_g_128, wg, &beta);
        let want = md((a1 + a2 * lam) * k as i64 + g1 + g2 * t) as usize;
        assert!(
            ref_eq_j(&out, &m[want]),
            "Q={k}G a=({a1},{a2}) g=({g1},{g2}): want {want}G"
        );
    };

    let qs: Vec<usize> = if full() {
        (1..199).collect()
    } else {
        vec![1, 2, 3, 92, 106, 155, 197, 198]
    };
    let nas: Vec<i64> = if full() {
        (0..ORD).collect()
    } else {
        (0..ORD).step_by(7).collect()
    };
    let lifts_per_q: u64 = if full() { 10_000 } else { 1_000 };
    let threads = 4usize;
    let calls = AtomicU64::new(0);
    let totals: Vec<Counts> = std::thread::scope(|sc| {
        (0..threads)
            .map(|th| {
                let (qs, nas, run, calls) = (&qs, &nas, &run, &calls);
                sc.spawn(move || {
                    branches::reset();
                    let mine: Vec<usize> = qs.iter().copied().skip(th).step_by(threads).collect();
                    let mut n_calls = 0u64;
                    for &k in &mine {
                        for &na in nas {
                            let (a1, a2) = split(na, lam);
                            for ng in 0..ORD {
                                let (g1, g2) = split(ng, t);
                                run(k, a1, a2, g1, g2);
                                n_calls += 1;
                            }
                        }
                        for a1 in -3..=3 {
                            for a2 in -3..=3 {
                                for g1 in -3..=3 {
                                    for g2 in -3..=3 {
                                        run(k, a1, a2, g1, g2);
                                        n_calls += 1;
                                    }
                                }
                            }
                        }
                    }
                    let mut r = SplitMix64(0x0074_3162 + th as u64);
                    let lift = |r: &mut SplitMix64, v: i64| -> i64 {
                        let bits = r.below(40);
                        let kk = (r.next_u64() & ((1u64 << bits) - 1)) as i64;
                        if r.below(2) == 0 {
                            v + ORD * kk
                        } else {
                            v - ORD * kk
                        }
                    };
                    for &k in &mine {
                        for _ in 0..lifts_per_q {
                            let (a1, a2) = split(r.below(199) as i64, lam);
                            let (g1, g2) = split(r.below(199) as i64, t);
                            let (a1, a2) = (lift(&mut r, a1), lift(&mut r, a2));
                            let (g1, g2) = (lift(&mut r, g1), lift(&mut r, g2));
                            run(k, a1, a2, g1, g2);
                            n_calls += 1;
                        }
                    }
                    calls.fetch_add(n_calls, Ordering::Relaxed);
                    branches::get()
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().expect("thread"))
            .collect()
    });
    let mut c = [[0u64; N_BRANCH]; N_SITE];
    for tc in &totals {
        for s in 0..N_SITE {
            for b in 0..N_BRANCH {
                c[s][b] += tc[s][b];
            }
        }
    }
    println!(
        "exhaustive Straus loop, order 199: {} calls over {} keys",
        calls.load(Ordering::Relaxed),
        qs.len()
    );
    for (s, name) in SITE_NAMES.iter().enumerate() {
        println!("  {name:>8}: {:?}", c[s]);
    }
    for s in [Site::A, Site::LambdaA, Site::G, Site::G128] {
        for b in [0usize, 1, 3, 4] {
            assert!(
                c[s as usize][b] > 0,
                "site {} branch {} never ran",
                SITE_NAMES[s as usize],
                BRANCH_NAMES[b]
            );
        }
        assert_eq!(c[s as usize][2], 0, "an addend at infinity in the loop");
    }
}
