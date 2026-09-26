// SPDX-License-Identifier: ISC
//! Property tests: algebraic laws over arbitrary values, plus agreement
//! with native u128 arithmetic on the range where they overlap (project
//! brief §7 layer 2 mandates a reference-arithmetic property suite for this
//! type).

// Reference-arithmetic assertions on guarded (nonzero/checked) values.
#![allow(clippy::arithmetic_side_effects)]

use proptest::prelude::*;

use dcroxide_uint256::Uint256;

fn arb_uint256() -> impl Strategy<Value = Uint256> {
    any::<[u8; 32]>().prop_map(|b| Uint256::from_be_bytes(&b))
}

fn from_u128(v: u128) -> Uint256 {
    let mut be = [0u8; 32];
    be[16..].copy_from_slice(&v.to_be_bytes());
    Uint256::from_be_bytes(&be)
}

/// A reference shift that moves one bit at a time through the
/// little-endian bytes, so it shares no code with the word-level shifts
/// under test: bit `i` of the result is bit `i - k` (left) or `i + k`
/// (right) of `a`, and zero where that falls outside 0..256.
fn ref_shift(a: Uint256, k: u32, left: bool) -> Uint256 {
    let src = a.to_le_bytes();
    let mut out = [0u8; 32];
    for i in 0..256u32 {
        let from = if left {
            i.checked_sub(k)
        } else {
            i.checked_add(k).filter(|&j| j < 256)
        };
        if let Some(j) = from
            && (src[(j / 8) as usize] >> (j % 8)) & 1 == 1
        {
            out[(i / 8) as usize] |= 1 << (i % 8);
        }
    }
    Uint256::from_le_bytes(&out)
}

/// `a` with every bit at or above `width` cleared, built bytewise.
fn low_bits(a: Uint256, width: u32) -> Uint256 {
    let mut le = a.to_le_bytes();
    for (i, b) in le.iter_mut().enumerate() {
        let lo = i as u32 * 8;
        if lo >= width {
            *b = 0;
        } else if width - lo < 8 {
            *b &= (1u8 << (width - lo)) - 1;
        }
    }
    Uint256::from_le_bytes(&le)
}

proptest! {
    #[test]
    fn add_sub_round_trip(a in arb_uint256(), b in arb_uint256()) {
        let mut v = a;
        v.add(&b);
        v.sub(&b);
        prop_assert_eq!(v, a);
    }

    #[test]
    fn mul_commutes(a in arb_uint256(), b in arb_uint256()) {
        let mut ab = a;
        ab.mul(&b);
        let mut ba = b;
        ba.mul(&a);
        prop_assert_eq!(ab, ba);
        // And squaring agrees with self-multiplication.
        let mut sq = a;
        sq.square();
        let mut aa = a;
        aa.mul(&a);
        prop_assert_eq!(sq, aa);
    }

    #[test]
    fn division_identity(a in arb_uint256(), b in arb_uint256()) {
        prop_assume!(!b.is_zero());
        // q*b + r == a with r < b (r computed as a - q*b).
        let mut q = a;
        q.div(&b);
        let mut qb = q;
        qb.mul(&b);
        let mut r = a;
        r.sub(&qb);
        prop_assert!(r < b);
        let mut back = qb;
        back.add(&r);
        prop_assert_eq!(back, a);
    }

    #[test]
    fn u128_agreement(x in any::<u128>(), y in any::<u128>()) {
        // Operations that stay within 256 bits agree with native math.
        let (a, b) = (from_u128(x), from_u128(y));
        let mut sum = a;
        sum.add(&b);
        if let Some(s) = x.checked_add(y) {
            prop_assert_eq!(sum, from_u128(s));
        }
        let mut prod = a;
        prod.mul(&b);
        if let Some(p) = x.checked_mul(y) {
            prop_assert_eq!(prod, from_u128(p));
        }
        if let Some(q) = x.checked_div(y) {
            let mut quo = a;
            quo.div(&b);
            prop_assert_eq!(quo, from_u128(q));
        }
        prop_assert_eq!(a.cmp(&b), x.cmp(&y));
        prop_assert_eq!(u32::from(a.bit_len()), 128 - x.leading_zeros());
    }

    #[test]
    fn shift_round_trip(a in arb_uint256(), k in 0u32..=260) {
        // Both shifts, in place and into another value, agree with the
        // bitwise reference, including every word offset and the carries
        // across words; past 255 bits the result is zero.
        let mut shl = a;
        shl.lsh(k);
        prop_assert_eq!(shl, ref_shift(a, k, true));
        let mut shr = a;
        shr.rsh(k);
        prop_assert_eq!(shr, ref_shift(a, k, false));
        let mut shl_val = Uint256::MAX;
        shl_val.lsh_val(&a, k);
        prop_assert_eq!(shl_val, shl);
        let mut shr_val = Uint256::MAX;
        shr_val.rsh_val(&a, k);
        prop_assert_eq!(shr_val, shr);

        // (a << k) >> k preserves the low 256-k bits and clears the rest.
        let mut v = a;
        v.lsh(k);
        v.rsh(k);
        prop_assert_eq!(v, low_bits(a, 256u32.saturating_sub(k)));

        // Below one word, shifting is multiplication and division by 2^k.
        if k < 64 {
            let mut mult = a;
            mult.mul_u64(1u64 << k);
            prop_assert_eq!(shl, mult);
            let mut quo = a;
            quo.div_u64(1u64 << k);
            prop_assert_eq!(shr, quo);
        }
    }

    #[test]
    fn bytes_and_negate_laws(a in arb_uint256()) {
        prop_assert_eq!(Uint256::from_be_bytes(&a.to_be_bytes()), a);
        prop_assert_eq!(Uint256::from_le_bytes(&a.to_le_bytes()), a);
        // -(-a) == a; a + (-a) == 0.
        let mut neg = a;
        neg.negate();
        let mut back = neg;
        back.negate();
        prop_assert_eq!(back, a);
        let mut zero = a;
        zero.add(&neg);
        prop_assert!(zero.is_zero());
        // not(not(a)) == a.
        let mut nn = a;
        nn.not();
        nn.not();
        prop_assert_eq!(nn, a);
    }
}
