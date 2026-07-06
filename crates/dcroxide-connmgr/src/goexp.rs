// SPDX-License-Identifier: ISC
//! A bit-exact port of Go's portable `math.Exp` (and the `math.Ldexp`
//! it uses), needed by the dynamic ban score decay.
//!
//! Go dispatches `math.Exp` to platform assembly on several
//! architectures, and those implementations differ from the portable
//! Go code by one ulp on some inputs, so dcrd's decayed ban scores
//! are already platform-dependent (QK-0006).  This port follows the
//! portable Go source, which is the specification at the tag.

// The algorithm is transcribed from Go's math/exp.go and ldexp.go;
// the constants and expression shapes match that source verbatim.
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::excessive_precision)]
#![allow(clippy::approx_constant)]
#![allow(clippy::manual_range_contains)]
#![allow(clippy::neg_multiply)]

/// Go `math.Ldexp`: frac × 2**exp.
pub fn ldexp(frac: f64, exp: i32) -> f64 {
    // Special cases.
    if frac == 0.0 {
        return frac; // correctly return -0
    }
    if frac.is_infinite() || frac.is_nan() {
        return frac;
    }
    let (frac, e) = normalize(frac);
    let mut exp = exp + e;
    let mut x = frac.to_bits();
    const MASK: i64 = 0x7ff;
    const SHIFT: u32 = 64 - 11 - 1;
    const BIAS: i64 = 1023;
    exp += (((x >> SHIFT) as i64) & MASK) as i32 - BIAS as i32;
    if exp < -1075 {
        return 0f64.copysign(frac); // underflow
    }
    if exp > 1023 {
        // Overflow.
        if frac < 0.0 {
            return f64::NEG_INFINITY;
        }
        return f64::INFINITY;
    }
    let mut m = 1f64;
    if exp < -1022 {
        // Denormal.
        exp += 53;
        m = 1.0 / (1u64 << 53) as f64; // 2**-53
    }
    x &= !((MASK as u64) << SHIFT);
    x |= ((exp as i64 + BIAS) as u64) << SHIFT;
    m * f64::from_bits(x)
}

/// Go `math.normalize`: the normal number equivalent and the exponent
/// adjustment.
fn normalize(x: f64) -> (f64, i32) {
    const SMALLEST_NORMAL: f64 = 2.2250738585072014e-308; // 2**-1022
    if x.abs() < SMALLEST_NORMAL {
        return (x * (1u64 << 52) as f64, -52);
    }
    (x, 0)
}

/// Go's portable `math.Exp`.
pub fn exp(x: f64) -> f64 {
    const LN2_HI: f64 = 6.93147180369123816490e-01;
    const LN2_LO: f64 = 1.90821492927058770002e-10;
    const LOG2_E: f64 = 1.44269504088896338700e+00;
    const OVERFLOW: f64 = 7.09782712893383973096e+02;
    const UNDERFLOW: f64 = -7.45133219101941108420e+02;
    const NEAR_ZERO: f64 = 1.0 / (1u64 << 28) as f64; // 2**-28

    // Special cases.
    if x.is_nan() {
        return x;
    }
    if x > OVERFLOW {
        return f64::INFINITY;
    }
    if x < UNDERFLOW {
        return 0.0;
    }
    if -NEAR_ZERO < x && x < NEAR_ZERO {
        return 1.0 + x;
    }

    // Reduce; computed as r = hi - lo for extra precision.
    let k: i32 = if x < 0.0 {
        (LOG2_E * x - 0.5) as i32
    } else if x > 0.0 {
        (LOG2_E * x + 0.5) as i32
    } else {
        0
    };
    let hi = x - (k as f64) * LN2_HI;
    let lo = (k as f64) * LN2_LO;

    expmulti(hi, lo, k)
}

/// Go `math.expmulti`: exp(hi - lo) × 2**k, |hi - lo| ≤ 0.5 × ln 2.
fn expmulti(hi: f64, lo: f64, k: i32) -> f64 {
    const P1: f64 = 1.66666666666666657415e-01;
    const P2: f64 = -2.77777777770155933842e-03;
    const P3: f64 = 6.61375632143793436117e-05;
    const P4: f64 = -1.65339022054652515390e-06;
    const P5: f64 = 4.13813679705723846039e-08;

    let r = hi - lo;
    let t = r * r;
    let c = r - t * (P1 + t * (P2 + t * (P3 + t * (P4 + t * P5))));
    let y = 1.0 - ((lo - (r * c) / (2.0 - c)) - hi);
    ldexp(y, k)
}
