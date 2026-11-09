// SPDX-License-Identifier: ISC AND MIT
//
// Derived from libsecp256k1 src/ecmult_impl.h (Copyright (c) 2013, 2014,
// 2017 Pieter Wuille, Andrew Poelstra, Jonas Nick), as vendored by
// secp256k1-sys 0.14.1.  MIT; see NOTICE.
//
//! The wNAF builder, libsecp256k1's `ecmult_wnaf` (ecmult_impl.h:155-221),
//! with the guard that keeps every half the Straus loop consumes within its
//! 129 positions.
//!
//! Each half that reaches the loop, a `split_lambda` half of the key's
//! scalar or a `split_128` half of the generator's, must fit [`WNAF_LEN`]
//! positions.  The C folds a half with bit 255 set (a value near N) by
//! negating it and flipping the digits' signs (:178-182), and checks that
//! the result fits only under VERIFY (`carry == 0` and no bit set from the
//! last position on, :208-219); in release an oversized half would be cut
//! short without a word.  Here the builder returns `None` when, after the
//! same fold, any bit at or above 128 is set or the final carry is
//! nonzero, so the check and the digits come from one function and cannot
//! disagree.  libsecp256k1's proof of the split's bounds (scalar_impl.h,
//! :182-286) says `None` never happens; the caller falls back if it does.

use crate::scalar::Scalar;

/// Positions in the wNAF of a 128-bit half: `WNAF_BITS + 1`
/// (ecmult_impl.h:44, and the 129-entry arrays of `ecmult_strauss_wnaf`).
pub(crate) const WNAF_LEN: usize = 129;

/// A wNAF digit type: `i8` for the key's window, `i16` for the
/// generator's.  A digit's magnitude is at most 2^(w-1) - 1.
pub(crate) trait Digit: Copy {
    /// Zero.
    const ZERO: Self;
    /// The largest window whose digits fit.
    const MAX_W: u32;
    /// Narrows a digit known to fit (debug-asserted).
    fn from_i32(v: i32) -> Self;
    /// Widens (tests).
    #[cfg(test)]
    fn to_i32(self) -> i32;
}

impl Digit for i8 {
    const ZERO: Self = 0;
    const MAX_W: u32 = 8;
    #[inline(always)]
    fn from_i32(v: i32) -> Self {
        debug_assert!(i8::try_from(v).is_ok());
        v as i8
    }
    #[cfg(test)]
    fn to_i32(self) -> i32 {
        i32::from(self)
    }
}

impl Digit for i16 {
    const ZERO: Self = 0;
    const MAX_W: u32 = 16;
    #[inline(always)]
    fn from_i32(v: i32) -> Self {
        debug_assert!(i16::try_from(v).is_ok());
        v as i16
    }
    #[cfg(test)]
    fn to_i32(self) -> i32 {
        i32::from(self)
    }
}

/// `ecmult_wnaf` (ecmult_impl.h:162-221) over [`WNAF_LEN`] positions with
/// window `w` (2 to `T::MAX_W`): writes digits with sum(2^i * wnaf\[i\]) =
/// a mod N (the sign folded in as the C folds it) and returns the number
/// of positions up to the last nonzero digit.  `None` when, after the
/// fold, the value has a bit set at or above 128, or the final carry is
/// nonzero.
#[inline]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "the C's int arithmetic: bit <= 129, now <= w <= 16, and word \
              below 2^16 + 1, so nothing leaves i32 or u32"
)]
pub(crate) fn try_wnaf<T: Digit>(wnaf: &mut [T; WNAF_LEN], a: &Scalar, w: u32) -> Option<usize> {
    debug_assert!((2..=31).contains(&w) && w <= T::MAX_W);
    let len = WNAF_LEN as u32;
    let mut last_set_bit: i32 = -1;
    let mut sign: i32 = 1;
    let mut carry: u32 = 0;

    for d in wnaf.iter_mut() {
        *d = T::ZERO;
    }

    let mut s = *a;
    if s.get_bits_limb32(255, 1) != 0 {
        s = s.negate();
        sign = -1;
    }

    // The guard: after the fold the half must be below 2^128.
    if (s.limbs()[2] | s.limbs()[3]) != 0 {
        return None;
    }

    let mut bit: u32 = 0;
    while bit < len {
        if s.get_bits_limb32(bit, 1) == carry {
            bit += 1;
            continue;
        }

        let now = if w > len - bit { len - bit } else { w };

        let mut word = s.get_bits_var(bit, now) as i32 + carry as i32;

        carry = ((word >> (w - 1)) & 1) as u32;
        word -= (carry as i32) << w;

        wnaf[bit as usize] = T::from_i32(sign * word);
        last_set_bit = bit as i32;

        bit += now;
    }

    // The C's VERIFY block (:208-219), its carry check made a release
    // check.  It cannot fire once the guard above holds: position 128 is
    // then 0 and absorbs any carry into the last chunk.  Kept as the C's
    // check, and the guard also rules out a set bit past the end.
    if carry != 0 {
        return None;
    }
    debug_assert!((bit..256).all(|b| s.get_bits_limb32(b, 1) == 0));
    Some((last_set_bit + 1) as usize)
}
