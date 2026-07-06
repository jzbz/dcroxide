// SPDX-License-Identifier: ISC
//! The DC-net finite field F = 2**127 - 1 (dcrd mixing `field.go`).
//!
//! dcrd computes over `math/big` integers reduced by a final
//! `Mod(F)`; every observable value is that canonical residue, so
//! this port carries canonical residues throughout in a `u128` with
//! Mersenne-prime folding.  Inputs longer than the field (such as
//! 32-byte hash digests or attacker-controlled wire values) are
//! reduced on entry, which yields identical results everywhere dcrd
//! reduces before producing output.

// Bounded message and vector arithmetic mirrors Go; genuinely
// wrapping math uses explicit wrapping operations.
#![allow(clippy::arithmetic_side_effects)]

/// The field prime 2**127 - 1 (dcrd `F`).
pub const F: u128 = (1u128 << 127) - 1;

/// A canonical residue of the field F.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct FieldInt(pub(crate) u128);

/// Fold a value below 2**128 into a canonical residue.
fn fold(x: u128) -> u128 {
    // 2**127 ≡ 1 (mod F): split and add, then normalize.
    let folded = (x & F).wrapping_add(x >> 127);
    if folded >= F { folded - F } else { folded }
}

// The arithmetic methods are named for the field operations they
// port rather than implementing the std operator traits.
#[allow(clippy::should_implement_trait)]
impl FieldInt {
    /// The zero element.
    pub const ZERO: FieldInt = FieldInt(0);

    /// Construct a residue from a small integer.
    pub fn from_u64(x: u64) -> FieldInt {
        FieldInt(u128::from(x))
    }

    /// Construct a residue from big-endian bytes of any length,
    /// reducing modulo F (dcrd `new(big.Int).SetBytes` composed with
    /// the eventual `Mod(F)`).
    pub fn from_be_bytes(bytes: &[u8]) -> FieldInt {
        let mut acc = FieldInt::ZERO;
        for &b in bytes {
            // acc = acc*256 + b
            acc = acc.mul(&FieldInt(256)).add(&FieldInt(u128::from(b)));
        }
        acc
    }

    /// The minimal big-endian encoding of the residue (Go
    /// `big.Int.Bytes()`: an empty slice for zero).
    pub fn to_be_bytes(self) -> Vec<u8> {
        if self.0 == 0 {
            return Vec::new();
        }
        let bytes = self.0.to_be_bytes();
        let first = bytes.iter().position(|&b| b != 0).unwrap_or(15);
        bytes[first..].to_vec()
    }

    /// Whether the residue is zero.
    pub fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Addition in F.
    pub fn add(self, other: &FieldInt) -> FieldInt {
        // Both operands are canonical (< 2**127), so the sum fits.
        FieldInt(fold(self.0.wrapping_add(other.0)))
    }

    /// Subtraction in F.
    pub fn sub(self, other: &FieldInt) -> FieldInt {
        FieldInt(fold(self.0.wrapping_add(F - other.0)))
    }

    /// Negation in F.
    pub fn neg(self) -> FieldInt {
        if self.0 == 0 {
            return FieldInt(0);
        }
        FieldInt(F - self.0)
    }

    /// Multiplication in F.
    pub fn mul(self, other: &FieldInt) -> FieldInt {
        // 128x128 -> 256 bit product via 64-bit limbs.
        let (a, b) = (self.0, other.0);
        let (a0, a1) = (a & u128::from(u64::MAX), a >> 64);
        let (b0, b1) = (b & u128::from(u64::MAX), b >> 64);

        let ll = a0.wrapping_mul(b0);
        let lh = a0.wrapping_mul(b1);
        let hl = a1.wrapping_mul(b0);
        let hh = a1.wrapping_mul(b1);

        // mid = lh + hl (can carry one bit past 128).
        let (mid, mid_carry) = lh.overflowing_add(hl);

        // lo = ll + (mid << 64); hi = hh + (mid >> 64) + carries.
        let (lo, lo_carry) = ll.overflowing_add(mid << 64);
        let mut hi = hh
            .wrapping_add(mid >> 64)
            .wrapping_add(u128::from(lo_carry));
        if mid_carry {
            hi = hi.wrapping_add(1u128 << 64);
        }

        // p = hi*2**128 + lo with p < 2**254; write p = c*2**127 + d.
        let d = lo & F;
        let c = (hi << 1) | (lo >> 127);
        FieldInt(fold(fold(c).wrapping_add(d)))
    }

    /// Exponentiation in F by a non-negative integer exponent.
    pub fn pow(self, mut exp: u128) -> FieldInt {
        let mut base = self;
        let mut result = FieldInt(1);
        while exp > 0 {
            if exp & 1 == 1 {
                result = result.mul(&base);
            }
            base = base.mul(&base);
            exp >>= 1;
        }
        result
    }

    /// The multiplicative inverse in F (F is prime, so Fermat's
    /// little theorem applies; dcrd uses `big.Int.ModInverse`).
    pub fn inv(self) -> FieldInt {
        self.pow(F - 2)
    }
}

/// Whether x, given as its canonical residue and an in-range marker,
/// is bounded by the field F (dcrd `InField`): the check over raw
/// big-endian bytes, since dcrd applies it to arbitrary-precision
/// wire values before reduction.
pub fn in_field_be_bytes(bytes: &[u8]) -> bool {
    // Values with more than 16 significant bytes exceed 2**128 > F.
    let significant: Vec<u8> = bytes.iter().copied().skip_while(|&b| b == 0).collect();
    if significant.len() > 16 {
        return false;
    }
    let mut buf = [0u8; 16];
    buf[16 - significant.len()..].copy_from_slice(&significant);
    u128::from_be_bytes(buf) < F
}
