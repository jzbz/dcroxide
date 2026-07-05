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
    fn shift_round_trip(a in arb_uint256(), k in 0u32..=256) {
        // (a << k) >> k preserves the low 256-k bits.
        let mut v = a;
        v.lsh(k);
        v.rsh(k);
        let mut masked = a;
        if k > 0 {
            masked.lsh(k.min(256));
            let mut m2 = masked;
            m2.rsh(k.min(256));
            prop_assert_eq!(v, m2);
        } else {
            prop_assert_eq!(v, a);
        }
        // Shifting left by k is multiplication by 2^k when k < 64.
        if k < 64 {
            let mut shifted = a;
            shifted.lsh(k);
            let mut mult = a;
            mult.mul_u64(1u64 << k);
            prop_assert_eq!(shifted, mult);
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
