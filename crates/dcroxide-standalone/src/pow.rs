// SPDX-License-Identifier: ISC
//! Proof-of-work checks, compact-bits conversions, and the DCP0011 ASERT
//! difficulty algorithm (dcrd blockchain/standalone `pow.go`).
//!
//! Like dcrd, this module works over arbitrary-precision signed integers
//! ([`BigInt`]): the compact representation encodes an 8-bit base-256
//! exponent and a sign bit, so decoded targets may be negative or exceed
//! 256 bits, and both must round-trip exactly.

use alloc::format;
use alloc::string::ToString;

use dcroxide_chainhash::Hash;
use num_bigint::{BigInt, Sign};

use crate::error::{ErrorKind, RuleError, rule_error};

/// Convert a hash into a big integer for math comparisons (dcrd
/// `HashToBig`).  The hash is little-endian, so the bytes are reversed.
pub fn hash_to_big(hash: &Hash) -> BigInt {
    let mut buf = hash.0;
    buf.reverse();
    BigInt::from_bytes_be(Sign::Plus, &buf)
}

/// Convert a compact representation of a whole number to a big integer
/// (dcrd `CompactToBig`).
///
/// Like IEEE754 floating point, the representation has a sign, an
/// exponent, and a mantissa: the most significant 8 bits are the
/// unsigned base-256 exponent, bit 23 is the sign, and the low 23 bits
/// are the mantissa.  N = (-1^sign) * mantissa * 256^(exponent-3).
pub fn compact_to_big(compact: u32) -> BigInt {
    // Extract the mantissa, sign bit, and exponent.
    let mut mantissa = compact & 0x007f_ffff;
    let is_negative = compact & 0x0080_0000 != 0;
    let exponent = compact >> 24;

    // Treat the exponent as the number of bytes and shift the mantissa
    // accordingly; equivalent to N = mantissa * 256^(exponent-3).
    let mut bn = if exponent <= 3 {
        mantissa >>= 8 * (3 - exponent);
        BigInt::from(mantissa)
    } else {
        BigInt::from(mantissa) << (8 * (exponent - 3))
    };

    // Make it negative if the sign bit is set.
    if is_negative {
        bn = -bn;
    }

    bn
}

/// Convert a whole number to its compact 32-bit representation (dcrd
/// `BigToCompact`).  The compact form only provides 23 bits of
/// precision, so larger values only encode the most significant digits.
pub fn big_to_compact(n: &BigInt) -> u32 {
    // No need to do any work if it's zero.
    if n.sign() == Sign::NoSign {
        return 0;
    }

    // Treat the exponent as the number of bytes of the magnitude and
    // shift the number right or left accordingly; equivalent to
    // mantissa = mantissa / 256^(exponent-3).
    //
    // Note that for negative values the shift below mirrors Go's
    // arithmetic (floor) `Rsh` on the signed value followed by taking
    // the low word of the magnitude, which can differ by one from
    // shifting the magnitude directly.
    let mut mantissa: u32;
    let mut exponent = n.magnitude().to_bytes_be().len();
    if exponent <= 3 {
        mantissa = n.magnitude().iter_u64_digits().next().unwrap_or(0) as u32;
        mantissa <<= 8 * (3 - exponent);
    } else {
        let shifted = n >> (8 * (exponent - 3));
        mantissa = shifted.magnitude().iter_u64_digits().next().unwrap_or(0) as u32;
    }

    // When the mantissa already has the sign bit set, the number is too
    // large to fit into the available 23 bits, so divide the number by
    // 256 and increment the exponent accordingly.
    if mantissa & 0x0080_0000 != 0 {
        mantissa >>= 8;
        exponent += 1;
    }

    // Pack the exponent, sign bit, and mantissa into an unsigned 32-bit
    // integer and return it.
    let mut compact = (exponent as u32) << 24 | mantissa;
    if n.sign() == Sign::Minus {
        compact |= 0x0080_0000;
    }
    compact
}

/// Calculate a work value from difficulty bits: (1 << 256) divided by
/// (target + 1), or zero for non-positive targets (dcrd `CalcWork`).
pub fn calc_work(bits: u32) -> BigInt {
    // Return a work value of zero if the passed difficulty bits
    // represent a negative number, which could happen in an invalid
    // block.
    let difficulty_num = compact_to_big(bits);
    if difficulty_num.sign() != Sign::Plus {
        return BigInt::from(0);
    }

    // (1 << 256) / (difficultyNum + 1)
    let one_lsh_256 = BigInt::from(1) << 256u32;
    let denominator = difficulty_num + 1;
    one_lsh_256 / denominator
}

/// Ensure the provided target difficulty is in min/max range per the
/// provided proof-of-work limit (dcrd `checkProofOfWorkRange`).
fn check_pow_range(target: &BigInt, pow_limit: &BigInt) -> Result<(), RuleError> {
    // The target difficulty must be larger than zero.
    if target.sign() != Sign::Plus {
        let str = format!("target difficulty of {target:064x} is too low");
        return Err(rule_error(ErrorKind::UnexpectedDifficulty, str));
    }

    // The target difficulty must be less than the maximum allowed.
    if target > pow_limit {
        let str =
            format!("target difficulty of {target:064x} is higher than max of {pow_limit:064x}");
        return Err(rule_error(ErrorKind::UnexpectedDifficulty, str));
    }

    Ok(())
}

/// Ensure the provided compact target difficulty is in min/max range per
/// the provided proof-of-work limit (dcrd `CheckProofOfWorkRange`).
pub fn check_proof_of_work_range(
    difficulty_bits: u32,
    pow_limit: &BigInt,
) -> Result<(), RuleError> {
    let target = compact_to_big(difficulty_bits);
    check_pow_range(&target, pow_limit)
}

/// Ensure the provided hash is less than the provided target difficulty
/// (dcrd `checkProofOfWorkHash`).
fn check_pow_hash(pow_hash: &Hash, target: &BigInt) -> Result<(), RuleError> {
    // The proof of work hash must be less than the target difficulty.
    let hash_num = hash_to_big(pow_hash);
    if hash_num > *target {
        let str = format!(
            "proof of work hash {hash_num:064x} is higher than expected max of {target:064x}"
        );
        return Err(rule_error(ErrorKind::HighHash, str));
    }

    Ok(())
}

/// Ensure the provided hash is less than the provided compact target
/// difficulty (dcrd `CheckProofOfWorkHash`).
pub fn check_proof_of_work_hash(pow_hash: &Hash, difficulty_bits: u32) -> Result<(), RuleError> {
    let target = compact_to_big(difficulty_bits);
    check_pow_hash(pow_hash, &target)
}

/// Ensure the provided hash is less than the provided compact target
/// difficulty and that the target is in range per the proof-of-work
/// limit (dcrd `CheckProofOfWork`).
pub fn check_proof_of_work(
    pow_hash: &Hash,
    difficulty_bits: u32,
    pow_limit: &BigInt,
) -> Result<(), RuleError> {
    let target = compact_to_big(difficulty_bits);
    check_pow_range(&target, pow_limit)?;

    // The proof of work hash must be less than the target difficulty.
    check_pow_hash(pow_hash, &target)
}

/// Calculate an absolutely scheduled exponentially weighted target
/// difficulty per DCP0011 (dcrd `CalcASERTDiff`).
///
/// The target difficulty is doubled or halved for every multiple of the
/// half life that the most recent block is ahead of or behind the ideal
/// schedule.  To avoid floating point math, the exponential term is
/// computed with 64.16 fixed-point arithmetic and a cubic polynomial
/// approximation of 2^x over [0, 1); see dcrd's implementation notes for
/// the full derivation, which this port follows step by step.
///
/// Panics when the starting difficulty is not in `[1, pow_limit]` or the
/// height delta is negative, exactly like dcrd.
pub fn calc_asert_diff(
    start_diff_bits: u32,
    pow_limit: &BigInt,
    target_secs_per_block: i64,
    time_delta: i64,
    height_delta: i64,
    half_life: i64,
) -> u32 {
    // Ensure parameter assumptions are not violated.
    //
    // 1. The starting target difficulty must be in the range [1, powLimit]
    // 2. The height to calculate the difficulty for must come after the
    //    height of the reference block
    let start_diff = compact_to_big(start_diff_bits);
    if start_diff.sign() != Sign::Plus || start_diff > *pow_limit {
        panic!(
            "starting difficulty {start_diff:064x} is not in the valid range [1, {pow_limit:064x}]"
        );
    }
    if height_delta < 0 {
        panic!("provided height delta {height_delta} is negative");
    }

    // Calculate the exponent (x) using 64.16 fixed point and decompose
    // it into integer (n, "shifts") and fractional (f) parts:
    //
    //   x = ((Δt - Δh*Ib) << 16) / halfLife   (truncated division)
    //   n = x >> 16
    //   f = x & 0xffff
    //
    // The subtraction and multiplication wrap on overflow exactly like
    // Go's int64 arithmetic.  The lossy narrowing casts below reproduce
    // Go's `Int64()` (low 64 bits, two's complement) for out-of-range
    // values.
    let ideal_time_delta = height_delta.wrapping_mul(target_secs_per_block);
    let exponent: i128 =
        (i128::from(time_delta.wrapping_sub(ideal_time_delta)) << 16) / i128::from(half_life);
    let frac64 = u64::from((exponent as i64 & 0xffff) as u16);
    let mut shifts = (exponent >> 16) as i64;

    // Calculate 2^16 * 2^(fractional part) of the exponent using the
    // 16.48 fixed-point cubic polynomial approximation.  The overall
    // result is guaranteed to be positive and a maximum of 17 bits.  The
    // interior arithmetic uses wrapping operations to match Go's uint64
    // exactly (the coefficients were chosen such that it does not
    // actually overflow).
    const POLY_COEFF1: u64 = 195766423245049; // ceil(0.695502049712533 * 2^48)
    const POLY_COEFF2: u64 = 971821376; // ceil(0.2262697964 * 2^32)
    const POLY_COEFF3: u64 = 5127; // ceil(0.0782318 * 2^16)
    let frac_factor: u32 = (1u64 << 16).wrapping_add(
        POLY_COEFF1
            .wrapping_mul(frac64)
            .wrapping_add(POLY_COEFF2.wrapping_mul(frac64).wrapping_mul(frac64))
            .wrapping_add(
                POLY_COEFF3
                    .wrapping_mul(frac64)
                    .wrapping_mul(frac64)
                    .wrapping_mul(frac64),
            )
            .wrapping_add(1u64 << 47)
            >> 48,
    ) as u32;

    // Calculate the target difficulty:
    //
    //   nextDiff = startDiff * 2^f * 2^n / 2^16
    //
    // where the division by 2^16 folds into the shift count.
    let mut next_diff = start_diff * BigInt::from(frac_factor);
    shifts -= 16;

    // Shift counts beyond these bounds are mathematically guaranteed to
    // clamp below (nextDiff is at least 2^16 before shifting and the
    // limit is under 2^256), so take the clamp directly rather than
    // materializing an enormous intermediate value like Go does.
    const MAX_MATERIALIZED_SHIFT: i64 = 8192;
    if shifts >= MAX_MATERIALIZED_SHIFT {
        return big_to_compact(pow_limit);
    }
    if shifts <= -MAX_MATERIALIZED_SHIFT {
        return big_to_compact(&BigInt::from(1));
    }
    if shifts >= 0 {
        next_diff <<= shifts as u64;
    } else {
        next_diff >>= (-shifts) as u64;
    }

    // Limit the target difficulty to the valid hardest and easiest
    // values: the range [1, powLimit].
    if next_diff.sign() == Sign::NoSign {
        // The hardest valid target difficulty is 1 since it would be
        // impossible to find a non-negative integer less than 0.
        next_diff = BigInt::from(1);
    } else if next_diff > *pow_limit {
        next_diff = pow_limit.clone();
    }

    // Convert the difficulty to the compact representation and return
    // it.
    big_to_compact(&next_diff)
}

/// Render a big integer as the decimal string Go's `big.Int.String`
/// produces; a convenience for dump-style tests.
pub fn big_to_string(n: &BigInt) -> alloc::string::String {
    n.to_string()
}
