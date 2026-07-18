// SPDX-License-Identifier: ISC
//! Overflow-checked integer addition helpers (dcrd
//! `internal/blockchain/checkedmath.go`, new in dcrd 2.2).
//!
//! Each returns the wrapping sum together with a flag that is true
//! when the result is safe to use (no overflow or underflow).  The
//! flag expressions mirror dcrd's exactly so the consensus rejection
//! points coincide bit for bit.

/// The sum of two unsigned integers of the same size and whether the
/// result is safe to use, i.e. no overflow occurred (dcrd
/// `addUnsigned`).
pub trait AddUnsigned: Sized {
    /// The wrapping sum and a flag that is true when no overflow
    /// occurred.
    fn add_unsigned(self, b: Self) -> (Self, bool);
}

/// The sum of two signed integers of the same size and whether the
/// result is safe to use, i.e. no overflow or underflow occurred
/// (dcrd `addSigned`).
pub trait AddSigned: Sized {
    /// The wrapping sum and a flag that is true when no overflow or
    /// underflow occurred.
    fn add_signed(self, b: Self) -> (Self, bool);
}

macro_rules! impl_add_unsigned {
    ($($t:ty),*) => {$(
        impl AddUnsigned for $t {
            #[inline]
            fn add_unsigned(self, b: $t) -> ($t, bool) {
                let sum = self.wrapping_add(b);
                (sum, sum >= self)
            }
        }
    )*};
}

macro_rules! impl_add_signed {
    ($($t:ty),*) => {$(
        impl AddSigned for $t {
            #[inline]
            fn add_signed(self, b: $t) -> ($t, bool) {
                // Overflow only occurs when adding a positive value
                // when the sum is <= the left summand.  Likewise,
                // underflow only occurs when adding a non-positive
                // value when the sum is > the left summand.  The
                // returned flag is the logical negation of testing
                // both conditions at once so it indicates their
                // absence.
                let sum = self.wrapping_add(b);
                (sum, (sum > self) == (b > 0))
            }
        }
    )*};
}

impl_add_unsigned!(u16, u32, u64);
impl_add_signed!(i16, i32, i64);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_unsigned_flags() {
        assert_eq!(3u32.add_unsigned(4), (7, true));
        assert_eq!(u32::MAX.add_unsigned(0), (u32::MAX, true));
        assert_eq!(u32::MAX.add_unsigned(1), (0, false));
        assert_eq!(u64::MAX.add_unsigned(2), (1, false));
        assert_eq!(0u16.add_unsigned(0), (0, true));
    }

    #[test]
    fn add_signed_flags() {
        assert_eq!(3i64.add_signed(4), (7, true));
        assert_eq!(i64::MAX.add_signed(1), (i64::MIN, false));
        assert_eq!(i64::MIN.add_signed(-1), (i64::MAX, false));
        assert_eq!(5i64.add_signed(-3), (2, true));
        assert_eq!(0i64.add_signed(0), (0, true));
        assert_eq!((-5i64).add_signed(-5), (-10, true));
        // Adding zero never overflows in either direction.
        assert_eq!(i64::MAX.add_signed(0), (i64::MAX, true));
        assert_eq!(i64::MIN.add_signed(0), (i64::MIN, true));
    }
}
