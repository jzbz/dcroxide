// SPDX-License-Identifier: ISC
//! Fixed-precision unsigned 256-bit integer arithmetic, ported from dcrd's
//! `math/uint256` package (module v1.0.2, as pinned by dcrd release-v2.1.5).
//!
//! All operations are performed modulo 2^256 with "wrap around" semantics,
//! exactly like dcrd. The consensus consumers are difficulty and cumulative
//! work calculations, where bit-for-bit parity matters (project brief §6
//! Phase 1); parity is pinned by a live differential test against dcrd's
//! own implementation via `tools/oracle`, plus property tests.
//!
//! The API mirrors dcrd's mutating, chainable style method-for-method so the
//! parity audit stays mechanical (`Add2`→[`Uint256::add2`], `LshVal`→
//! [`Uint256::lsh_val`], …). Not ported: the `big.Int` interop (`SetBig`/
//! `ToBig`/`PutBig` — Go-specific) and the `fmt.Formatter` implementation
//! (Rust's formatting traits are provided instead; the parity surface for
//! text output is [`Uint256::text`], which matches dcrd's `Text` exactly).

#![cfg_attr(not(test), no_std)]
// This crate is 2^256 modular arithmetic: wrapping is the specified
// semantics, carried out through explicit carry/borrow helpers, and all
// indexing is over fixed 4/5-word arrays with statically bounded loops.
#![allow(clippy::arithmetic_side_effects)]

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use core::cmp::Ordering;
use core::fmt;

/// `a + b + carry`, returning the sum and new carry (Go `bits.Add64`).
#[inline]
fn add64(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let (d1, c1) = a.overflowing_add(b);
    let (d2, c2) = d1.overflowing_add(carry);
    (d2, u64::from(c1) + u64::from(c2))
}

/// `a - b - borrow`, returning the difference and new borrow
/// (Go `bits.Sub64`).
#[inline]
fn sub64(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let (d1, b1) = a.overflowing_sub(b);
    let (d2, b2) = d1.overflowing_sub(borrow);
    (d2, u64::from(b1) | u64::from(b2))
}

/// The 128-bit product of `a * b` as (hi, lo) (Go `bits.Mul64`).
#[inline]
fn mul64(a: u64, b: u64) -> (u64, u64) {
    let t = u128::from(a) * u128::from(b);
    ((t >> 64) as u64, t as u64)
}

/// `(hi‖lo) / y` returning (quotient, remainder); requires `hi < y` so the
/// quotient fits in 64 bits (Go `bits.Div64` under the same precondition).
#[inline]
fn div64(hi: u64, lo: u64, y: u64) -> (u64, u64) {
    debug_assert!(hi < y);
    let dividend = (u128::from(hi) << 64) | u128::from(lo);
    let y128 = u128::from(y);
    ((dividend / y128) as u64, (dividend % y128) as u64)
}

/// `digit1*digit2 + m` as (hi, lo) (dcrd `mulAdd64`).
#[inline]
fn mul_add64(digit1: u64, digit2: u64, m: u64) -> (u64, u64) {
    let t = u128::from(digit1) * u128::from(digit2) + u128::from(m);
    ((t >> 64) as u64, t as u64)
}

/// `digit1*digit2 + m + c` as (hi, lo) (dcrd `mulAdd64Carry`).
#[inline]
fn mul_add64_carry(digit1: u64, digit2: u64, m: u64, c: u64) -> (u64, u64) {
    let t = u128::from(digit1) * u128::from(digit2) + u128::from(m) + u128::from(c);
    ((t >> 64) as u64, t as u64)
}

/// The supported output bases for [`Uint256::text`] (dcrd `OutputBase`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputBase {
    /// Base 2.
    Binary,
    /// Base 8.
    Octal,
    /// Base 10.
    Decimal,
    /// Base 16 (lowercase).
    Hex,
}

/// High-performance, unsigned 256-bit fixed-precision integer with
/// modulo-2^256 wrap-around semantics, byte-compatible with dcrd's
/// `Uint256`.
///
/// Internally represented as 4 unsigned 64-bit words in base 2^64, least
/// significant word first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct Uint256 {
    n: [u64; 4],
}

impl Uint256 {
    /// The value zero.
    pub const ZERO: Uint256 = Uint256 { n: [0; 4] };

    /// The maximum value (2^256 - 1).
    pub const MAX: Uint256 = Uint256 { n: [u64::MAX; 4] };

    /// A uint256 from an unsigned 64-bit integer (dcrd `SetUint64`).
    pub const fn from_u64(v: u64) -> Uint256 {
        Uint256 { n: [v, 0, 0, 0] }
    }

    /// A uint256 from a 256-bit big-endian byte array (dcrd `SetBytes`).
    pub fn from_be_bytes(b: &[u8; 32]) -> Uint256 {
        let w = |i: usize| u64::from_be_bytes(b[i..i + 8].try_into().expect("8 bytes"));
        Uint256 {
            n: [w(24), w(16), w(8), w(0)],
        }
    }

    /// A uint256 from a 256-bit little-endian byte array (dcrd
    /// `SetBytesLE`).
    pub fn from_le_bytes(b: &[u8; 32]) -> Uint256 {
        let w = |i: usize| u64::from_le_bytes(b[i..i + 8].try_into().expect("8 bytes"));
        Uint256 {
            n: [w(0), w(8), w(16), w(24)],
        }
    }

    /// A uint256 from a big-endian byte slice, truncated to the final 32
    /// bytes so the result is modulo 2^256 (dcrd `SetByteSlice`).
    pub fn from_be_slice(b: &[u8]) -> Uint256 {
        let mut b32 = [0u8; 32];
        let take = b.len().min(32);
        let src = &b[b.len() - take..];
        b32[32 - take..].copy_from_slice(src);
        Uint256::from_be_bytes(&b32)
    }

    /// A uint256 from a little-endian byte slice, truncated to the first 32
    /// bytes so the result is modulo 2^256 (dcrd `SetByteSliceLE`).
    pub fn from_le_slice(b: &[u8]) -> Uint256 {
        let mut b32 = [0u8; 32];
        let take = b.len().min(32);
        b32[..take].copy_from_slice(&b[..take]);
        Uint256::from_le_bytes(&b32)
    }

    /// The value as a 32-byte big-endian array (dcrd `Bytes`).
    pub fn to_be_bytes(self) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0..8].copy_from_slice(&self.n[3].to_be_bytes());
        b[8..16].copy_from_slice(&self.n[2].to_be_bytes());
        b[16..24].copy_from_slice(&self.n[1].to_be_bytes());
        b[24..32].copy_from_slice(&self.n[0].to_be_bytes());
        b
    }

    /// The value as a 32-byte little-endian array (dcrd `BytesLE`).
    pub fn to_le_bytes(self) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0..8].copy_from_slice(&self.n[0].to_le_bytes());
        b[8..16].copy_from_slice(&self.n[1].to_le_bytes());
        b[16..24].copy_from_slice(&self.n[2].to_le_bytes());
        b[24..32].copy_from_slice(&self.n[3].to_le_bytes());
        b
    }

    /// Set to zero (dcrd `Zero`).
    pub fn zero(&mut self) -> &mut Uint256 {
        self.n = [0; 4];
        self
    }

    /// Set to the given value (dcrd `Set`).
    pub fn set(&mut self, n2: &Uint256) -> &mut Uint256 {
        *self = *n2;
        self
    }

    /// Set to the given unsigned 64-bit integer (dcrd `SetUint64`).
    pub fn set_u64(&mut self, v: u64) -> &mut Uint256 {
        self.n = [v, 0, 0, 0];
        self
    }

    /// Whether the value is zero (dcrd `IsZero`).
    pub fn is_zero(&self) -> bool {
        self.n == [0; 4]
    }

    /// Whether the value is odd (dcrd `IsOdd`).
    pub fn is_odd(&self) -> bool {
        self.n[0] & 1 == 1
    }

    /// Whether the value fits a u32 without truncation (dcrd `IsUint32`).
    pub fn is_u32(&self) -> bool {
        (self.n[0] >> 32 | self.n[1] | self.n[2] | self.n[3]) == 0
    }

    /// The low-order 32 bits (the value modulo 2^32; dcrd `Uint32`).
    pub fn as_u32(&self) -> u32 {
        self.n[0] as u32
    }

    /// Whether the value fits a u64 without truncation (dcrd `IsUint64`).
    pub fn is_u64(&self) -> bool {
        (self.n[1] | self.n[2] | self.n[3]) == 0
    }

    /// The low-order 64 bits (the value modulo 2^64; dcrd `Uint64`).
    pub fn as_u64(&self) -> u64 {
        self.n[0]
    }

    /// Whether the value equals the given u64 (dcrd `EqUint64`).
    pub fn eq_u64(&self, n2: u64) -> bool {
        self.n[0] == n2 && (self.n[1] | self.n[2] | self.n[3]) == 0
    }

    /// Whether the value is less than the given u64 (dcrd `LtUint64`).
    pub fn lt_u64(&self, n2: u64) -> bool {
        self.n[0] < n2 && (self.n[1] | self.n[2] | self.n[3]) == 0
    }

    /// Whether the value is <= the given u64 (dcrd `LtEqUint64`).
    pub fn lt_eq_u64(&self, n2: u64) -> bool {
        self.n[0] <= n2 && (self.n[1] | self.n[2] | self.n[3]) == 0
    }

    /// Whether the value is greater than the given u64 (dcrd `GtUint64`).
    pub fn gt_u64(&self, n2: u64) -> bool {
        self.n[0] > n2 || (self.n[1] | self.n[2] | self.n[3]) != 0
    }

    /// Whether the value is >= the given u64 (dcrd `GtEqUint64`).
    pub fn gt_eq_u64(&self, n2: u64) -> bool {
        !self.lt_u64(n2)
    }

    /// Compare with a u64 (dcrd `CmpUint64`).
    pub fn cmp_u64(&self, n2: u64) -> Ordering {
        if self.lt_u64(n2) {
            return Ordering::Less;
        }
        if self.gt_u64(n2) {
            return Ordering::Greater;
        }
        Ordering::Equal
    }

    /// self = n1 + n2 (mod 2^256) (dcrd `Add2`).
    pub fn add2(&mut self, n1: &Uint256, n2: &Uint256) -> &mut Uint256 {
        let mut c = 0;
        (self.n[0], c) = add64(n1.n[0], n2.n[0], c);
        (self.n[1], c) = add64(n1.n[1], n2.n[1], c);
        (self.n[2], c) = add64(n1.n[2], n2.n[2], c);
        (self.n[3], _) = add64(n1.n[3], n2.n[3], c);
        self
    }

    /// self += n2 (mod 2^256) (dcrd `Add`).
    pub fn add(&mut self, n2: &Uint256) -> &mut Uint256 {
        let n1 = *self;
        self.add2(&n1, n2)
    }

    /// self += n2 (mod 2^256) for a u64 (dcrd `AddUint64`).
    pub fn add_u64(&mut self, n2: u64) -> &mut Uint256 {
        let mut c = 0;
        (self.n[0], c) = add64(self.n[0], n2, c);
        (self.n[1], c) = add64(self.n[1], 0, c);
        (self.n[2], c) = add64(self.n[2], 0, c);
        (self.n[3], _) = add64(self.n[3], 0, c);
        self
    }

    /// self = n1 - n2 (mod 2^256) (dcrd `Sub2`).
    pub fn sub2(&mut self, n1: &Uint256, n2: &Uint256) -> &mut Uint256 {
        let mut borrow = 0;
        (self.n[0], borrow) = sub64(n1.n[0], n2.n[0], borrow);
        (self.n[1], borrow) = sub64(n1.n[1], n2.n[1], borrow);
        (self.n[2], borrow) = sub64(n1.n[2], n2.n[2], borrow);
        (self.n[3], _) = sub64(n1.n[3], n2.n[3], borrow);
        self
    }

    /// self -= n2 (mod 2^256) (dcrd `Sub`).
    pub fn sub(&mut self, n2: &Uint256) -> &mut Uint256 {
        let n1 = *self;
        self.sub2(&n1, n2)
    }

    /// self -= n2 (mod 2^256) for a u64 (dcrd `SubUint64`).
    pub fn sub_u64(&mut self, n2: u64) -> &mut Uint256 {
        let mut borrow = 0;
        (self.n[0], borrow) = sub64(self.n[0], n2, borrow);
        (self.n[1], borrow) = sub64(self.n[1], 0, borrow);
        (self.n[2], borrow) = sub64(self.n[2], 0, borrow);
        (self.n[3], _) = sub64(self.n[3], 0, borrow);
        self
    }

    /// self = n1 * n2 (mod 2^256) (dcrd `Mul2`).
    ///
    /// Schoolbook multiplication computing only the terms below 2^256, per
    /// dcrd's optimized structure.
    pub fn mul2(&mut self, n1: &Uint256, n2: &Uint256) -> &mut Uint256 {
        let (r0, mut r1, mut r2, mut r3, mut c): (u64, u64, u64, u64, u64);

        (c, r0) = mul64(n2.n[0], n1.n[0]);
        (c, r1) = mul_add64(n2.n[0], n1.n[1], c);
        (c, r2) = mul_add64(n2.n[0], n1.n[2], c);
        r3 = n2.n[0].wrapping_mul(n1.n[3]).wrapping_add(c);

        (c, r1) = mul_add64(n2.n[1], n1.n[0], r1);
        (c, r2) = mul_add64_carry(n2.n[1], n1.n[1], r2, c);
        r3 = r3.wrapping_add(n2.n[1].wrapping_mul(n1.n[2]).wrapping_add(c));

        (c, r2) = mul_add64(n2.n[2], n1.n[0], r2);
        r3 = r3.wrapping_add(n2.n[2].wrapping_mul(n1.n[1]).wrapping_add(c));

        r3 = r3.wrapping_add(n2.n[3].wrapping_mul(n1.n[0]));

        self.n = [r0, r1, r2, r3];
        self
    }

    /// self *= n2 (mod 2^256) (dcrd `Mul`).
    pub fn mul(&mut self, n2: &Uint256) -> &mut Uint256 {
        let n1 = *self;
        self.mul2(&n1, n2)
    }

    /// self *= n2 (mod 2^256) for a u64 (dcrd `MulUint64`).
    pub fn mul_u64(&mut self, n2: u64) -> &mut Uint256 {
        let mut c;
        (c, self.n[0]) = mul64(self.n[0], n2);
        (c, self.n[1]) = mul_add64(self.n[1], n2, c);
        (c, self.n[2]) = mul_add64(self.n[2], n2, c);
        self.n[3] = self.n[3].wrapping_mul(n2).wrapping_add(c);
        self
    }

    /// self = n2^2 (mod 2^256) (dcrd `SquareVal`).
    pub fn square_val(&mut self, n2: &Uint256) -> &mut Uint256 {
        let (r0, mut r1, mut r2, mut r3, mut c): (u64, u64, u64, u64, u64);

        (c, r0) = mul64(n2.n[0], n2.n[0]);
        (c, r1) = mul_add64(n2.n[0], n2.n[1], c);
        (c, r2) = mul_add64(n2.n[0], n2.n[2], c);
        r3 = c;

        (c, r1) = mul_add64(n2.n[1], n2.n[0], r1);
        (c, r2) = mul_add64_carry(n2.n[1], n2.n[1], r2, c);
        r3 = r3.wrapping_add(c);

        (c, r2) = mul_add64(n2.n[2], n2.n[0], r2);
        r3 = r3.wrapping_add(c);

        r3 = r3.wrapping_add(
            2u64.wrapping_mul(
                n2.n[0]
                    .wrapping_mul(n2.n[3])
                    .wrapping_add(n2.n[1].wrapping_mul(n2.n[2])),
            ),
        );

        self.n = [r0, r1, r2, r3];
        self
    }

    /// self = self^2 (mod 2^256) (dcrd `Square`).
    pub fn square(&mut self) -> &mut Uint256 {
        let n2 = *self;
        self.square_val(&n2)
    }

    /// The number of base-2^64 digits required to represent the value; 0
    /// for zero (dcrd `numDigits`).
    fn num_digits(&self) -> usize {
        for i in (0..4).rev() {
            if self.n[i] != 0 {
                return i + 1;
            }
        }
        0
    }

    /// self = dividend / divisor (truncated; mod 2^256) (dcrd `Div2`).
    ///
    /// # Panics
    ///
    /// Panics when the divisor is zero, exactly like dcrd.
    pub fn div2(&mut self, dividend: &Uint256, divisor: &Uint256) -> &mut Uint256 {
        assert!(!divisor.is_zero(), "division by zero");

        // Fast paths: divisor larger than dividend, equal values, and
        // dividends that fit a native u64.
        if divisor > dividend {
            return self.zero();
        }
        if dividend == divisor {
            return self.set_u64(1);
        }
        if dividend.is_u64() {
            return self.set_u64(dividend.n[0] / divisor.n[0]);
        }

        // Single-digit divisors use the schoolbook short division; the long
        // division below requires at least two divisor digits.
        if divisor.is_u64() {
            let mut quotient = Uint256::ZERO;
            let mut r = 0u64;
            for d in (0..dividend.num_digits()).rev() {
                (quotient.n[d], r) = div64(r, dividend.n[d], divisor.n[0]);
            }
            return self.set(&quotient);
        }

        // Knuth Algorithm 4.3.1D long division (with the dcrd modifications
        // for full 64-bit words and conditional correction); see dcrd's
        // extensively documented original for the full rationale.
        //
        // Normalize both operands so the divisor's leading digit is >= 2^63.
        let num_divisor_digits = divisor.num_digits();
        let num_dividend_digits = dividend.num_digits();
        let sf = divisor.n[num_divisor_digits - 1].leading_zeros();
        let mut divisor_n = [0u64; 4];
        let mut dividend_n = [0u64; 5];
        if sf > 0 {
            for i in (1..num_divisor_digits).rev() {
                divisor_n[i] = divisor.n[i] << sf | divisor.n[i - 1] >> (64 - sf);
            }
            divisor_n[0] = divisor.n[0] << sf;

            dividend_n[num_dividend_digits] = dividend.n[num_dividend_digits - 1] >> (64 - sf);
            for i in (1..num_dividend_digits).rev() {
                dividend_n[i] = dividend.n[i] << sf | dividend.n[i - 1] >> (64 - sf);
            }
            dividend_n[0] = dividend.n[0] << sf;
        } else {
            divisor_n[..4].copy_from_slice(&divisor.n);
            dividend_n[..4].copy_from_slice(&dividend.n);
        }

        // Compute one quotient digit per iteration via a (possibly
        // overestimated by at most two) estimate that is corrected against
        // the active part of the remainder.
        let mut p = [0u64; 5];
        let (mut qhat, mut c, mut borrow): (u64, u64, u64);
        self.zero();
        for d in (0..=num_dividend_digits - num_divisor_digits).rev() {
            // Estimate from the top two remainder digits over the leading
            // divisor digit; saturate on the equal-leading-digit overflow
            // case.
            if dividend_n[d + num_divisor_digits] == divisor_n[num_divisor_digits - 1] {
                qhat = u64::MAX;
            } else {
                (qhat, _) = div64(
                    dividend_n[d + num_divisor_digits],
                    dividend_n[d + num_divisor_digits - 1],
                    divisor_n[num_divisor_digits - 1],
                );
            }

            // p = qhat * divisor (as a 320-bit product).
            (c, p[0]) = mul64(qhat, divisor_n[0]);
            (c, p[1]) = mul_add64(qhat, divisor_n[1], c);
            (c, p[2]) = mul_add64(qhat, divisor_n[2], c);
            (p[4], p[3]) = mul_add64(qhat, divisor_n[3], c);

            // Correct the (rare) overestimate; runs at most twice.
            while prefix_lt(
                &dividend_n[d..d + num_divisor_digits + 1],
                &p[..num_divisor_digits + 1],
            ) {
                qhat -= 1;
                (p[0], borrow) = sub64(p[0], divisor_n[0], 0);
                (p[1], borrow) = sub64(p[1], divisor_n[1], borrow);
                (p[2], borrow) = sub64(p[2], divisor_n[2], borrow);
                (p[3], borrow) = sub64(p[3], divisor_n[3], borrow);
                p[4] = p[4].wrapping_sub(borrow);
            }

            self.n[d] = qhat;

            // Update the active part of the remainder.
            (dividend_n[d], borrow) = sub64(dividend_n[d], p[0], 0);
            (dividend_n[d + 1], borrow) = sub64(dividend_n[d + 1], p[1], borrow);
            (dividend_n[d + 2], _) = sub64(dividend_n[d + 2], p[2], borrow);
        }

        self
    }

    /// self /= divisor (truncated) (dcrd `Div`). Panics on a zero divisor.
    pub fn div(&mut self, divisor: &Uint256) -> &mut Uint256 {
        let dividend = *self;
        self.div2(&dividend, divisor)
    }

    /// self /= divisor (truncated) for a u64 divisor (dcrd `DivUint64`).
    /// Panics on a zero divisor.
    pub fn div_u64(&mut self, divisor: u64) -> &mut Uint256 {
        assert!(divisor != 0, "division by zero");

        if self.lt_u64(divisor) {
            return self.zero();
        }
        if self.eq_u64(divisor) {
            return self.set_u64(1);
        }

        let mut quotient = Uint256::ZERO;
        let mut r = 0u64;
        for d in (0..self.num_digits()).rev() {
            (quotient.n[d], r) = div64(r, self.n[d], divisor);
        }
        self.set(&quotient)
    }

    /// self = -n2 (mod 2^256), i.e. the two's complement (dcrd `NegateVal`).
    pub fn negate_val(&mut self, n2: &Uint256) -> &mut Uint256 {
        let mut borrow = 0;
        (self.n[0], borrow) = sub64(0, n2.n[0], borrow);
        (self.n[1], borrow) = sub64(0, n2.n[1], borrow);
        (self.n[2], borrow) = sub64(0, n2.n[2], borrow);
        (self.n[3], _) = sub64(0, n2.n[3], borrow);
        self
    }

    /// self = -self (mod 2^256) (dcrd `Negate`).
    pub fn negate(&mut self) -> &mut Uint256 {
        let n2 = *self;
        self.negate_val(&n2)
    }

    /// self = n2 << bits (dcrd `LshVal`). Shifts > 255 produce zero.
    pub fn lsh_val(&mut self, n2: &Uint256, bits: u32) -> &mut Uint256 {
        if bits > 255 {
            return self.zero();
        }
        if bits == 0 {
            return self.set(n2);
        }

        let mut bits = bits;
        if bits >= 192 {
            self.n = [0, 0, 0, n2.n[0]];
            bits -= 192;
            if bits == 0 {
                return self;
            }
            self.n[3] <<= bits;
            return self;
        }
        if bits >= 128 {
            self.n = [0, 0, n2.n[0], n2.n[1]];
            bits -= 128;
            if bits == 0 {
                return self;
            }
            self.n[3] = (self.n[3] << bits) | (self.n[2] >> (64 - bits));
            self.n[2] <<= bits;
            return self;
        }
        if bits >= 64 {
            self.n = [0, n2.n[0], n2.n[1], n2.n[2]];
            bits -= 64;
            if bits == 0 {
                return self;
            }
            self.n[3] = (self.n[3] << bits) | (self.n[2] >> (64 - bits));
            self.n[2] = (self.n[2] << bits) | (self.n[1] >> (64 - bits));
            self.n[1] <<= bits;
            return self;
        }

        self.n[3] = (n2.n[3] << bits) | (n2.n[2] >> (64 - bits));
        self.n[2] = (n2.n[2] << bits) | (n2.n[1] >> (64 - bits));
        self.n[1] = (n2.n[1] << bits) | (n2.n[0] >> (64 - bits));
        self.n[0] = n2.n[0] << bits;
        self
    }

    /// self <<= bits (dcrd `Lsh`).
    pub fn lsh(&mut self, bits: u32) -> &mut Uint256 {
        if bits == 0 {
            return self;
        }
        let n2 = *self;
        self.lsh_val(&n2, bits)
    }

    /// self = n2 >> bits (dcrd `RshVal`). Shifts > 255 produce zero.
    pub fn rsh_val(&mut self, n2: &Uint256, bits: u32) -> &mut Uint256 {
        if bits > 255 {
            return self.zero();
        }
        if bits == 0 {
            return self.set(n2);
        }

        let mut bits = bits;
        if bits >= 192 {
            self.n = [n2.n[3], 0, 0, 0];
            bits -= 192;
            if bits == 0 {
                return self;
            }
            self.n[0] >>= bits;
            return self;
        }
        if bits >= 128 {
            self.n = [n2.n[2], n2.n[3], 0, 0];
            bits -= 128;
            if bits == 0 {
                return self;
            }
            self.n[0] = (self.n[0] >> bits) | (self.n[1] << (64 - bits));
            self.n[1] >>= bits;
            return self;
        }
        if bits >= 64 {
            self.n = [n2.n[1], n2.n[2], n2.n[3], 0];
            bits -= 64;
            if bits == 0 {
                return self;
            }
            self.n[0] = (self.n[0] >> bits) | (self.n[1] << (64 - bits));
            self.n[1] = (self.n[1] >> bits) | (self.n[2] << (64 - bits));
            self.n[2] >>= bits;
            return self;
        }

        self.n[0] = (n2.n[0] >> bits) | (n2.n[1] << (64 - bits));
        self.n[1] = (n2.n[1] >> bits) | (n2.n[2] << (64 - bits));
        self.n[2] = (n2.n[2] >> bits) | (n2.n[3] << (64 - bits));
        self.n[3] = n2.n[3] >> bits;
        self
    }

    /// self >>= bits (dcrd `Rsh`).
    pub fn rsh(&mut self, bits: u32) -> &mut Uint256 {
        if bits == 0 {
            return self;
        }
        let n2 = *self;
        self.rsh_val(&n2, bits)
    }

    /// self = !self (bitwise not) (dcrd `Not`).
    pub fn not(&mut self) -> &mut Uint256 {
        for w in &mut self.n {
            *w = !*w;
        }
        self
    }

    /// self |= n2 (dcrd `Or`).
    pub fn or(&mut self, n2: &Uint256) -> &mut Uint256 {
        for (w, w2) in self.n.iter_mut().zip(&n2.n) {
            *w |= *w2;
        }
        self
    }

    /// self &= n2 (dcrd `And`).
    pub fn and(&mut self, n2: &Uint256) -> &mut Uint256 {
        for (w, w2) in self.n.iter_mut().zip(&n2.n) {
            *w &= *w2;
        }
        self
    }

    /// self ^= n2 (dcrd `Xor`).
    pub fn xor(&mut self, n2: &Uint256) -> &mut Uint256 {
        for (w, w2) in self.n.iter_mut().zip(&n2.n) {
            *w ^= *w2;
        }
        self
    }

    /// The minimum number of bits required to represent the value; 0 for
    /// zero (dcrd `BitLen`).
    pub fn bit_len(&self) -> u16 {
        for i in (0..4).rev() {
            if self.n[i] != 0 {
                return (64 - self.n[i].leading_zeros() + 64 * i as u32) as u16;
            }
        }
        0
    }

    /// The string representation in the given base (dcrd `Text`). Matches
    /// dcrd's digit-for-digit, including "0" for zero in every base.
    pub fn text(self, base: OutputBase) -> String {
        match base {
            OutputBase::Binary => self.to_radix_pow2(1),
            OutputBase::Octal => self.to_radix_pow2(3),
            OutputBase::Decimal => self.to_decimal(),
            OutputBase::Hex => self.to_radix_pow2(4),
        }
    }

    /// Base-2^shift conversion for shift in {1, 3, 4} (dcrd
    /// `toBin`/`toOctal`/`toHex`, sharing one generic implementation with
    /// identical output).
    fn to_radix_pow2(self, shift: u32) -> String {
        if self.is_zero() {
            return String::from("0");
        }
        const ALPHABET: &[u8; 16] = b"0123456789abcdef";
        let mask = (1u64 << shift) - 1;
        let bit_len = u32::from(self.bit_len());
        let max_out_digits = bit_len.div_ceil(shift);
        let mut result = vec![0u8; max_out_digits as usize];

        let mut out_idx = max_out_digits as usize;
        let mut bit = 0u32;
        while bit < bit_len {
            // Assemble the digit from up to two adjacent words.
            let word_idx = (bit / 64) as usize;
            let bit_in_word = bit % 64;
            let mut digit = self.n[word_idx] >> bit_in_word;
            if bit_in_word + shift > 64 && word_idx + 1 < 4 {
                digit |= self.n[word_idx + 1] << (64 - bit_in_word);
            }
            out_idx -= 1;
            result[out_idx] = ALPHABET[(digit & mask) as usize];
            bit += shift;
        }

        // Trim any leading zero produced by the ceiling division above.
        let first_nonzero = result.iter().position(|&b| b != b'0').unwrap_or(0);
        result.drain(..first_nonzero);
        String::from_utf8(result).expect("ASCII digits")
    }

    /// Base-10 conversion (dcrd `toDecimal`): divide out 10^19 chunks and
    /// convert each with native math.
    fn to_decimal(self) -> String {
        if self.is_zero() {
            return String::from("0");
        }
        const MAX_POW10: u64 = 10_000_000_000_000_000_000; // 10^19
        const OUTPUT_DIGITS_PER_DIV: u32 = 19;

        // bit_len / log2(10) + 1 digits suffice (see dcrd's derivation;
        // dcrd's literal is the same f64 value as the stdlib constant, and
        // this only sizes an over-allocated buffer that gets trimmed).
        let max_out_digits =
            (f64::from(u32::from(self.bit_len())) / core::f64::consts::LOG2_10) as u32 + 1;
        let mut result = vec![b'0'; max_out_digits as usize];

        let mut out_idx = max_out_digits as usize;
        let mut remaining_digits_per_div = 0u32;
        let mut quo = self;
        while !quo.is_zero() {
            for _ in 0..remaining_digits_per_div {
                out_idx -= 1;
                result[out_idx] = b'0';
            }
            remaining_digits_per_div = OUTPUT_DIGITS_PER_DIV;

            let rem = quo;
            quo.div_u64(MAX_POW10);
            let mut t = Uint256::ZERO;
            t.mul2(&quo, &Uint256::from_u64(MAX_POW10));
            let mut input_word = {
                let mut r = rem;
                r.sub(&t);
                r.as_u64()
            };
            while input_word != 0 {
                let r = input_word % 10;
                input_word /= 10;
                out_idx -= 1;
                result[out_idx] = b'0' + r as u8;
                remaining_digits_per_div -= 1;
            }
        }

        result.drain(..out_idx);
        String::from_utf8(result).expect("ASCII digits")
    }
}

/// Whether `a < b[..a.len()]` treating both as little-endian digit strings
/// (dcrd `prefixLt`).
fn prefix_lt(a: &[u64], b: &[u64]) -> bool {
    let mut borrow = 0;
    for i in 0..a.len() {
        (_, borrow) = sub64(a[i], b[i], borrow);
    }
    borrow != 0
}

impl Ord for Uint256 {
    /// Numeric comparison (dcrd `Cmp`/`Lt`/`Gt` and friends).
    fn cmp(&self, other: &Uint256) -> Ordering {
        let mut borrow = 0;
        let mut nonzero = 0u64;
        for i in 0..4 {
            let r;
            (r, borrow) = sub64(self.n[i], other.n[i], borrow);
            nonzero |= r;
        }
        if borrow != 0 {
            return Ordering::Less;
        }
        if nonzero == 0 {
            return Ordering::Equal;
        }
        Ordering::Greater
    }
}

impl PartialOrd for Uint256 {
    fn partial_cmp(&self, other: &Uint256) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl From<u64> for Uint256 {
    fn from(v: u64) -> Uint256 {
        Uint256::from_u64(v)
    }
}

impl fmt::Display for Uint256 {
    /// Decimal, like dcrd's `String`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad_integral(true, "", &self.to_decimal())
    }
}

impl fmt::Binary for Uint256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad_integral(true, "0b", &self.to_radix_pow2(1))
    }
}

impl fmt::Octal for Uint256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad_integral(true, "0o", &self.to_radix_pow2(3))
    }
}

impl fmt::LowerHex for Uint256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad_integral(true, "0x", &self.to_radix_pow2(4))
    }
}

impl fmt::UpperHex for Uint256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad_integral(true, "0x", &self.to_radix_pow2(4).to_uppercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_hex(s: &str) -> Uint256 {
        let mut padded = String::new();
        for _ in 0..64 - s.len() {
            padded.push('0');
        }
        padded.push_str(s);
        let bytes: [u8; 32] = dcroxide_testutil::unhex(&padded).try_into().expect("32");
        Uint256::from_be_bytes(&bytes)
    }

    #[test]
    fn bytes_round_trips() {
        let v = from_hex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        assert_eq!(Uint256::from_be_bytes(&v.to_be_bytes()), v);
        assert_eq!(Uint256::from_le_bytes(&v.to_le_bytes()), v);
        // Slice forms truncate modulo 2^256 (BE keeps the final 32 bytes,
        // LE the first 32).
        let mut long = vec![0xAB; 5];
        long.extend_from_slice(&v.to_be_bytes());
        assert_eq!(Uint256::from_be_slice(&long), v);
        let mut long_le = v.to_le_bytes().to_vec();
        long_le.extend_from_slice(&[0xCD; 5]);
        assert_eq!(Uint256::from_le_slice(&long_le), v);
    }

    #[test]
    fn arithmetic_edges() {
        // Max + 1 wraps to zero.
        let mut n = Uint256::MAX;
        n.add_u64(1);
        assert!(n.is_zero());

        // 0 - 1 wraps to max.
        let mut n = Uint256::ZERO;
        n.sub_u64(1);
        assert_eq!(n, Uint256::MAX);

        // Negate is the two's complement.
        let mut n = Uint256::from_u64(1);
        n.negate();
        assert_eq!(n, Uint256::MAX);

        // (2^128 - 1)^2 = 2^256 - 2^129 + 1 (mod 2^256).
        let mut n = from_hex("ffffffffffffffffffffffffffffffff");
        n.square();
        assert_eq!(
            n,
            from_hex("fffffffffffffffffffffffffffffffe00000000000000000000000000000001")
        );
    }

    #[test]
    fn division_edges() {
        // Divisor > dividend, equal, u64 fast paths, multi-digit divisor.
        let mut n = Uint256::from_u64(5);
        n.div(&Uint256::from_u64(10));
        assert!(n.is_zero());

        let big = from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        let mut n = big;
        n.div(&big);
        assert!(n.eq_u64(1));

        // max / (2^128 + 3): exercises the Knuth path with correction
        // potential.
        let divisor = from_hex("100000000000000000000000000000003");
        let mut q = big;
        q.div(&divisor);
        // Verify via multiplication: q*divisor <= big < (q+1)*divisor.
        let mut prod = Uint256::ZERO;
        prod.mul2(&q, &divisor);
        assert!(prod <= big);
        let mut next = q;
        next.add_u64(1);
        let mut prod_next = Uint256::ZERO;
        prod_next.mul2(&next, &divisor);
        // (q+1)*divisor either overflows (wraps below) or exceeds big.
        assert!(prod_next > big || prod_next < prod);
    }

    #[test]
    #[should_panic(expected = "division by zero")]
    fn div_by_zero_panics() {
        let mut n = Uint256::from_u64(1);
        n.div(&Uint256::ZERO);
    }

    #[test]
    fn shifts() {
        let one = Uint256::from_u64(1);
        for bits in [0u32, 1, 63, 64, 65, 127, 128, 129, 191, 192, 193, 255] {
            let mut n = one;
            n.lsh(bits);
            let mut back = n;
            back.rsh(bits);
            assert_eq!(back, one, "lsh/rsh {bits}");
            assert_eq!(n.bit_len(), (bits + 1) as u16, "bit_len at {bits}");
        }
        let mut n = one;
        n.lsh(256);
        assert!(n.is_zero());
    }

    #[test]
    fn text_bases() {
        let v = Uint256::from_u64(0xdeadbeef);
        assert_eq!(v.text(OutputBase::Hex), "deadbeef");
        assert_eq!(v.text(OutputBase::Decimal), "3735928559");
        assert_eq!(v.text(OutputBase::Octal), "33653337357");
        assert_eq!(
            v.text(OutputBase::Binary),
            "11011110101011011011111011101111"
        );
        assert_eq!(Uint256::ZERO.text(OutputBase::Hex), "0");
        assert_eq!(Uint256::ZERO.text(OutputBase::Decimal), "0");

        // A full-width value in base 10.
        assert_eq!(
            Uint256::MAX.text(OutputBase::Decimal),
            "115792089237316195423570985008687907853269984665640564039457584007913129639935"
        );
    }

    #[test]
    fn comparisons() {
        let a = Uint256::from_u64(5);
        let mut b = Uint256::from_u64(5);
        assert_eq!(a.cmp(&b), Ordering::Equal);
        b.lsh(200);
        assert!(a < b);
        assert!(b > a);
        assert!(a.lt_u64(6) && !a.lt_u64(5));
        assert!(a.gt_u64(4) && !a.gt_u64(5));
        assert!(b.gt_u64(u64::MAX));
        assert_eq!(a.cmp_u64(5), Ordering::Equal);
    }
}
