// SPDX-License-Identifier: ISC
//! The deterministic ticket lottery PRNG and index selection (dcrd stake
//! `lottery.go`). The treap-backed `fetchWinners` belongs to the ticket
//! state piece and is not here.

use alloc::format;
use alloc::vec::Vec;

use dcroxide_chainhash::{Hash, hash_h};

use crate::error::{ErrorKind, RuleError, stake_rule_error};

/// A constant derived from the hex representation of pi, mixed with the
/// caller-provided seed when initializing the PRNG (dcrd `seedConst`).
const SEED_CONST: [u8; 8] = [0x24, 0x3F, 0x6A, 0x88, 0x85, 0xA3, 0x08, 0xD3];

/// A deterministic pseudorandom number generator over BLAKE-256 producing
/// u32s from an initial seed (dcrd `Hash256PRNG`).
pub struct Hash256Prng {
    /// The seed used to initialize.
    seed: Hash,
    /// Position in the cached hash.
    hash_idx: usize,
    /// Position in the hash iterator.
    idx: u64,
    /// Cached last hash used.
    last_hash: Hash,
}

/// The initialization vector for a given seed (dcrd `CalcHash256PRNGIV`);
/// usable with [`Hash256Prng::from_iv`] to reproduce
/// [`Hash256Prng::new`]'s stream.
pub fn calc_hash256_prng_iv(seed: &[u8]) -> Hash {
    let mut buf = Vec::with_capacity(seed.len() + SEED_CONST.len());
    buf.extend_from_slice(seed);
    buf.extend_from_slice(&SEED_CONST);
    hash_h(&buf)
}

impl Hash256Prng {
    /// A PRNG from a precomputed initialization vector (dcrd
    /// `NewHash256PRNGFromIV`).
    pub fn from_iv(iv: Hash) -> Hash256Prng {
        Hash256Prng {
            seed: iv,
            hash_idx: 0,
            idx: 0,
            last_hash: iv,
        }
    }

    /// A PRNG from a seed (dcrd `NewHash256PRNG`).
    pub fn new(seed: &[u8]) -> Hash256Prng {
        Hash256Prng::from_iv(calc_hash256_prng_iv(seed))
    }

    /// A hash referencing the current state (dcrd `StateHash`).
    pub fn state_hash(&self) -> Hash {
        let mut final_state = [0u8; 32 + 4 + 1];
        final_state[..32].copy_from_slice(&self.last_hash.0);
        final_state[32..36].copy_from_slice(&(self.idx as u32).to_be_bytes());
        final_state[36] = self.hash_idx as u8;
        hash_h(&final_state)
    }

    /// The next random u32, updating the state (dcrd `Hash256Rand`).
    pub fn hash256_rand(&mut self) -> u32 {
        let start = self.hash_idx * 4;
        let r = u32::from_be_bytes(
            self.last_hash.0[start..start + 4]
                .try_into()
                .expect("4 bytes"),
        );
        self.hash_idx += 1;

        // 'Roll over' the hash index to use and store it.
        if self.hash_idx > 7 {
            let mut buf = [0u8; 36];
            buf[..32].copy_from_slice(&self.seed.0);
            buf[32..].copy_from_slice(&(self.idx as u32).to_be_bytes());
            self.last_hash = hash_h(&buf);
            self.idx += 1;
            self.hash_idx = 0;
        }

        // 'Roll over' the PRNG by re-hashing the seed when idx overflows.
        if self.idx > 0xFFFF_FFFF {
            self.seed = hash_h(&self.seed.0);
            self.last_hash = self.seed;
            self.idx = 0;
        }

        r
    }

    /// A random value in `[0, upper_bound)` avoiding modulo bias (dcrd
    /// `UniformRandom`, ported from arc4random_uniform).
    pub fn uniform_random(&mut self, upper_bound: u32) -> u32 {
        if upper_bound < 2 {
            return 0;
        }

        let min: u32 = if upper_bound > 0x8000_0000 {
            1u32.wrapping_add(!upper_bound)
        } else {
            // (2**32 - (x * 2)) % x == 2**32 % x when x <= 2**31
            (0xFFFF_FFFFu32
                .wrapping_sub(upper_bound.wrapping_mul(2))
                .wrapping_add(1))
                % upper_bound
        };

        let mut r;
        loop {
            r = self.hash256_rand();
            if r >= min {
                break;
            }
        }

        r % upper_bound
    }
}

/// Find `n` unique ticket indexes from a live ticket pool of the given
/// size (dcrd `findTicketIdxs`; private there but exercised through the
/// public PRNG, exposed here for the ticket-state machinery and tests).
pub fn find_ticket_idxs(
    size: usize,
    n: u16,
    prng: &mut Hash256Prng,
) -> Result<Vec<usize>, RuleError> {
    if size < usize::from(n) {
        return Err(stake_rule_error(
            ErrorKind::FindTicketIdxs,
            format!("cannot pick {n} unique ticket indexes from a live tickets size of {size}"),
        ));
    }

    const MAX: u64 = 0xFFFF_FFFF;
    if size as u64 > MAX {
        return Err(stake_rule_error(
            ErrorKind::FindTicketIdxs,
            format!("live tickets size ({size}) exceeds maximum allowed ({MAX})"),
        ));
    }
    let sz = size as u32;

    let mut list: Vec<usize> = Vec::with_capacity(usize::from(n));
    while list.len() < usize::from(n) {
        let r = prng.uniform_random(sz) as usize;
        if !list.contains(&r) {
            list.push(r);
        }
    }

    Ok(list)
}
