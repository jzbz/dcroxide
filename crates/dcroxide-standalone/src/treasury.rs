// SPDX-License-Identifier: ISC
//! Treasury spend voting window math (dcrd blockchain/standalone
//! `treasury.go`).

use alloc::format;

use crate::error::{ErrorKind, RuleError, rule_error};

/// The only valid expiry relative to the next block height where a
/// treasury spend transaction will expire (dcrd `CalcTSpendExpiry`).
/// Two blocks are added at the end because transaction expiry is
/// inclusive (>=) relative to block height.
pub fn calc_tspend_expiry(next_block_height: i64, tvi: u64, multiplier: u64) -> u32 {
    // The unsigned casts and wrapping operations mirror Go's uint64
    // arithmetic exactly, including for hostile inputs.
    let nbh = next_block_height as u64;
    let next_tvi = nbh.wrapping_add(tvi - (nbh % tvi)); // Round up to next TVI
    let max_tvi = next_tvi.wrapping_add(tvi.wrapping_mul(multiplier)); // Max TVI allowed.

    max_tvi.wrapping_add(2) as u32 // + 2 to deal with Expiry handling in mempool.
}

/// Whether the passed height is on a treasury vote interval and is not 0
/// (dcrd `IsTreasuryVoteInterval`).
pub fn is_treasury_vote_interval(height: u64, tvi: u64) -> bool {
    height.is_multiple_of(tvi) && height != 0
}

/// Calculate the start and end of a treasury voting window from the
/// given expiry (dcrd `CalcTSpendWindow`).  Errors when the expiry is
/// not two more than a treasury vote interval or is before a single
/// voting window is possible.
pub fn calc_tspend_window(expiry: u32, tvi: u64, multiplier: u64) -> Result<(u32, u32), RuleError> {
    // Ensure the provided expiry is at least higher than a single voting
    // window.  Wrapping matches Go's uint64 arithmetic.
    let min_req_expiry = tvi.wrapping_mul(multiplier).wrapping_add(2);
    if u64::from(expiry) < min_req_expiry {
        let str = format!(
            "expiry {expiry} must be at least {min_req_expiry} for the voting window \
             defined by a TVI of {tvi} with a multiplier of {multiplier}"
        );
        return Err(rule_error(ErrorKind::InvalidTSpendExpiry, str));
    }

    // Ensure the provided expiry is two more than a TVI.  The wrapping
    // subtraction matches Go's uint32 arithmetic: a hostile TVI and
    // multiplier can wrap the minimum-expiry guard above, letting an
    // expiry below two through to here.
    if !is_treasury_vote_interval(u64::from(expiry.wrapping_sub(2)), tvi) {
        let str = format!(
            "expiry {expiry} must be two more than a multiple of the treasury vote \
             interval {tvi}"
        );
        return Err(rule_error(ErrorKind::InvalidTSpendExpiry, str));
    }

    Ok((
        expiry
            .wrapping_sub(tvi.wrapping_mul(multiplier) as u32)
            .wrapping_sub(2),
        expiry.wrapping_sub(2),
    ))
}

/// Whether the provided block height is inside the treasury vote window
/// of the provided expiry (dcrd `InsideTSpendWindow`).  The end is
/// INCLUSIVE in order to determine if a treasury spend is allowed in a
/// block despite the fact that the voting window is EXCLUSIVE.
pub fn inside_tspend_window(block_height: i64, expiry: u32, tvi: u64, multiplier: u64) -> bool {
    let Ok((start, end)) = calc_tspend_window(expiry, tvi, multiplier) else {
        return false;
    };

    block_height as u32 >= start && block_height as u32 <= end
}
