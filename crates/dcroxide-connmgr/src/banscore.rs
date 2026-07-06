// SPDX-License-Identifier: ISC
//! Dynamic ban scores (dcrd connmgr `dynamicbanscore.go`).

// The decay and range expressions mirror the Go source verbatim.
#![allow(clippy::neg_multiply)]
#![allow(clippy::manual_range_contains)]

use crate::goexp::exp;

/// The time (in seconds) by which the transient part of the ban score
/// decays to one half of its original value (dcrd `Halflife`).
pub const HALFLIFE: i64 = 60;

/// The decaying constant (dcrd `lambda`).
const LAMBDA: f64 = core::f64::consts::LN_2 / HALFLIFE as f64;

/// The maximum age of the transient part of the ban score to be
/// considered a non-zero score, in seconds (dcrd `Lifetime`).
pub const LIFETIME: i64 = 1800;

/// The number of decay factors (one per second) precomputed at
/// initialization (dcrd `precomputedLen`).
const PRECOMPUTED_LEN: usize = 64;

/// The decay factor at t seconds (dcrd `decayFactor`).
fn decay_factor(t: i64) -> f64 {
    // dcrd precomputes the first factors at init; computing them on
    // demand through the same expression is bit-identical.
    let _ = PRECOMPUTED_LEN;
    exp(-1.0 * t as f64 * LAMBDA)
}

/// Dynamic ban score consisting of a persistent and a decaying
/// component (dcrd `DynamicBanScore`).  The zero value is immediately
/// ready for use.
///
/// dcrd's mutex is daemon-phase concurrency, and its exported methods
/// consult the wall clock; the port takes explicit unix-second
/// timestamps, mirroring the unexported methods dcrd tests against.
#[derive(Default, Debug)]
pub struct DynamicBanScore {
    last_unix: i64,
    transient: f64,
    persistent: u32,
}

impl DynamicBanScore {
    /// A zero-valued ban score.
    pub fn new() -> DynamicBanScore {
        DynamicBanScore::default()
    }

    /// The ban score as a human-readable string as of the given time
    /// (dcrd `String`).
    pub fn to_string_at(&self, now_unix: i64) -> String {
        format!(
            "persistent {} + transient {} at {} = {} as of now",
            self.persistent,
            dcroxide_dcrjson::gojson::format_float_g(self.transient),
            self.last_unix,
            self.int_at(now_unix),
        )
    }

    /// The ban score at the given time: the sum of the persistent and
    /// decaying scores (dcrd `int`, backing the exported `Int`).
    pub fn int_at(&self, now_unix: i64) -> u32 {
        let dt = now_unix.wrapping_sub(self.last_unix);
        if self.transient < 1.0 || dt < 0 || LIFETIME < dt {
            return self.persistent;
        }
        self.persistent
            .wrapping_add((self.transient * decay_factor(dt)) as u32)
    }

    /// Increase the persistent and decaying scores as if the action
    /// happened at the given time, returning the resulting score (dcrd
    /// `increase`, backing the exported `Increase`).
    pub fn increase_at(&mut self, persistent: u32, transient: u32, now_unix: i64) -> u32 {
        self.persistent = self.persistent.wrapping_add(persistent);
        let tu = now_unix;
        let dt = tu.wrapping_sub(self.last_unix);

        if transient > 0 {
            if LIFETIME < dt {
                self.transient = 0.0;
            } else if self.transient > 1.0 && dt > 0 {
                self.transient *= decay_factor(dt);
            }
            self.transient += transient as f64;
            self.last_unix = tu;
        }
        self.persistent.wrapping_add(self.transient as u32)
    }

    /// Set both the persistent and decaying scores to zero (dcrd
    /// `Reset`).
    pub fn reset(&mut self) {
        self.persistent = 0;
        self.transient = 0.0;
        self.last_unix = 0;
    }
}

/// The raw decay factor for a given age, exposed for the frozen
/// whole-domain vectors.
#[doc(hidden)]
pub fn decay_factor_bits(t: i64) -> u64 {
    decay_factor(t).to_bits()
}
