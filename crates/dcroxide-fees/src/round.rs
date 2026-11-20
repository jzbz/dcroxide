// SPDX-License-Identifier: ISC

//! Go's `math.Round`, in `core` alone.
//!
//! dcrd's `EstimateFee` rounds the median fee rate with `math.Round`.
//! Rust's `f64::round` is std's, so a no_std build of this crate cannot
//! call it (CI's no_std job checks it on `x86_64-unknown-none`). Go
//! writes `math.Round` in Go on the double's bits (`math/floor.go`;
//! unlike `Floor`, `Ceil` and `Trunc` it has no assembly form), and the
//! go1.27.3 compiler replaces the call with one rounding instruction on
//! arm64, ppc64 and s390x
//! (`cmd/compile/internal/ssagen/intrinsics.go:759-763`), which also
//! rounds half away from zero; [`round`] is the Go function line for
//! line. Both it and `f64::round` round half away from zero and are
//! exact, so they agree on every input: the tests hold them to each other
//! on every exponent and on random bit patterns, and to Go's own
//! `TestRound` vectors.

/// Bits below the exponent field (Go's `shift`).
const SHIFT: u32 = 52;
/// The exponent field, once shifted down (Go's `mask`).
const MASK: u64 = 0x7ff;
/// The exponent bias (Go's `bias`).
const BIAS: u64 = 1023;
/// The biased exponent of a number in [0.5, 1) (Go's `bias-1`).
const BIAS_LESS_ONE: u64 = 1022;
/// The first biased exponent with no fraction bits (Go's `bias+shift`).
const BIAS_PLUS_SHIFT: u64 = 1075;
/// The sign bit (Go's `signMask`).
const SIGN_MASK: u64 = 1 << 63;
/// The bits of 1.0 (Go's `uvone`).
const UV_ONE: u64 = 0x3ff0_0000_0000_0000;
/// The fraction field (Go's `fracMask`).
const FRAC_MASK: u64 = (1 << SHIFT) - 1;
/// Half of one unit at the fraction's top bit (Go's `half`).
const HALF: u64 = 1 << (SHIFT - 1);

/// The nearest integer to `x`, halves rounded away from zero, with
/// zeros, infinities and NaNs returned as they are and the sign of a
/// result that rounds to zero kept (Go `math.Round`).
pub(crate) fn round(x: f64) -> f64 {
    let mut bits = x.to_bits();
    let e = (bits >> SHIFT) & MASK;
    if e < BIAS {
        // |x| < 1, subnormals included: a signed zero, or a signed one
        // from 0.5 up.
        bits &= SIGN_MASK;
        if e == BIAS_LESS_ONE {
            bits |= UV_ONE;
        }
    } else if e < BIAS_PLUS_SHIFT {
        // 1 <= |x| < 2^52, the range where a double can hold a fraction:
        // add a half at the units bit's position and clear the bits below
        // it. A carry out of the
        // fraction field moves into the exponent, which is the rounded
        // value's (as in Go). Larger exponents are integers, infinities
        // or NaNs and come back unchanged.
        //
        // `e - BIAS` is 0..=51 here, so neither the subtraction nor the
        // shifts wrap, and the sum stays below the exponent field's top.
        let unit = e.wrapping_sub(BIAS) as u32;
        bits = bits.wrapping_add(HALF.wrapping_shr(unit));
        bits &= !FRAC_MASK.wrapping_shr(unit);
    }
    f64::from_bits(bits)
}

#[cfg(test)]
mod tests {
    use super::round;

    /// Go's `alike`: both NaN, or equal with the same sign.
    fn alike(a: f64, b: f64) -> bool {
        (a.is_nan() && b.is_nan()) || (a == b && a.is_sign_negative() == b.is_sign_negative())
    }

    /// Go's `TestRound` (`math/all_test.go` at go1.27.3): its `vf`
    /// inputs against `round`, and `vfroundSC`. The inputs keep Go's
    /// seventeen-digit spelling, so they read as upstream's do.
    #[test]
    #[allow(clippy::excessive_precision)]
    fn go_test_round() {
        let vf = [
            4.979_011_924_883_673_5e0,
            7.738_872_474_578_104_5e0,
            -2.768_800_571_920_015_9e-1,
            -5.010_603_618_271_074_9e0,
            9.636_293_707_198_417_3e0,
            2.926_377_239_243_964_6e0,
            5.229_083_431_459_306_6e0,
            2.727_939_910_436_010_2e0,
            1.825_308_091_680_855_0e0,
            -8.685_924_768_575_601_3e0,
        ];
        let want = [5.0, 8.0, -0.0, -5.0, 10.0, 3.0, 5.0, 3.0, 2.0, -9.0];
        for (x, w) in vf.into_iter().zip(want) {
            assert!(
                alike(round(x), w),
                "round({x:e}) = {:e}, want {w:e}",
                round(x)
            );
        }
        let special = [
            (0.0, 0.0),
            (1.390_671_161_567e-309, 0.0),
            (0.499_999_999_999_999_94, 0.0),
            (0.5, 1.0),
            (0.500_000_000_000_000_1, 1.0),
            (-1.5, -2.0),
            (-2.5, -3.0),
            (f64::NAN, f64::NAN),
            (f64::INFINITY, f64::INFINITY),
            (2_251_799_813_685_249.5, 2_251_799_813_685_250.0),
            (2_251_799_813_685_250.5, 2_251_799_813_685_251.0),
            (4_503_599_627_370_495.5, 4_503_599_627_370_496.0),
            (4_503_599_627_370_497.0, 4_503_599_627_370_497.0),
        ];
        for (x, w) in special {
            assert!(
                alike(round(x), w),
                "round({x:e}) = {:e}, want {w:e}",
                round(x)
            );
        }
    }

    /// Every biased exponent, both signs, with fractions at and around
    /// each bit that decides a rounding, against std's `f64::round`
    /// (the tests build with std). NaNs are compared bit for bit: Go's
    /// returns its input unchanged.
    #[test]
    fn agrees_with_std_on_every_exponent() {
        let mut fractions: Vec<u64> = vec![0, 1, (1 << 52) - 1, 1 << 51, (1 << 51) - 1];
        for b in 0..52 {
            let bit = 1u64 << b;
            fractions.extend([bit, bit - 1, bit | 1, (bit - 1) ^ ((1 << 52) - 1)]);
        }
        for sign in [0, 1u64 << 63] {
            for e in 0..=0x7ffu64 {
                for &f in &fractions {
                    let x = f64::from_bits(sign | (e << 52) | (f & ((1 << 52) - 1)));
                    let got = round(x);
                    if x.is_nan() {
                        assert_eq!(got.to_bits(), x.to_bits());
                    } else {
                        assert!(alike(got, x.round()), "round({x:e}) = {got:e}");
                    }
                }
            }
        }
    }

    /// Ten million pseudo-random bit patterns (splitmix64, fixed seed)
    /// against std's `f64::round`.
    #[test]
    fn agrees_with_std_on_random_bits() {
        let mut state = 0x0123_4567_89ab_cdefu64;
        for _ in 0..10_000_000 {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^= z >> 31;
            let x = f64::from_bits(z);
            let got = round(x);
            if x.is_nan() {
                assert_eq!(got.to_bits(), x.to_bits());
            } else {
                assert!(alike(got, x.round()), "round({x:e}) = {got:e}");
            }
        }
    }
}
