// SPDX-License-Identifier: ISC
//! Branch counters for the group formulas and the Straus loop (test
//! builds only).  Each formula records the branch it took
//! ([`note`], called from `group.rs`), and the loop counts that branch
//! per call site ([`hit`], called from `ecmult.rs`), so the tests can
//! require every special case of every addition site to have run.  The
//! counters are per thread; production files hold only the `cfg(test)`
//! calls, so the crate outside its tests needs `core` alone.

use core::cell::Cell;

/// Which path a formula took.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Branch {
    /// The generic formula.
    Generic = 0,
    /// The accumulator (first operand) was infinity.
    AccInfinity = 1,
    /// The addend (second operand) was infinity.
    AddendInfinity = 2,
    /// Equal points: the addition doubled.
    Doubling = 3,
    /// Opposite points: the sum is infinity.
    Opposite = 4,
}

/// The number of [`Branch`] values.
pub(crate) const N_BRANCH: usize = 5;

/// Branch names, for reports.
pub(crate) const BRANCH_NAMES: [&str; N_BRANCH] = [
    "generic",
    "acc-infinity",
    "addend-infinity",
    "doubling",
    "opposite",
];

/// A call site of the Straus loop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Site {
    /// The doubling at the top of each position (`gej_double_var`).
    Double = 0,
    /// A's table (`gej_add_ge_var`).
    A = 1,
    /// lambda*A's table (`gej_add_ge_var`).
    LambdaA = 2,
    /// G's table (`gej_add_zinv_var`).
    G = 3,
    /// 2^128*G's table (`gej_add_zinv_var`).
    G128 = 4,
}

/// The number of [`Site`] values.
pub(crate) const N_SITE: usize = 5;

/// Site names, for reports.
pub(crate) const SITE_NAMES: [&str; N_SITE] = ["double", "A", "lambda*A", "G", "2^128*G"];

/// The counters: hits per site and branch.
pub(crate) type Counts = [[u64; N_BRANCH]; N_SITE];

std::thread_local! {
    static LAST: Cell<Branch> = const { Cell::new(Branch::Generic) };
    static HITS: Cell<Counts> = const { Cell::new([[0; N_BRANCH]; N_SITE]) };
}

/// Records the branch a formula took.
pub(crate) fn note(b: Branch) {
    LAST.with(|c| c.set(b));
}

/// The branch the last formula on this thread took.
pub(crate) fn last() -> Branch {
    LAST.with(Cell::get)
}

/// Counts the last formula's branch at `site`.
pub(crate) fn hit(site: Site) {
    let b = last() as usize;
    HITS.with(|h| {
        let mut c = h.get();
        c[site as usize][b] += 1;
        h.set(c);
    });
}

/// Zeroes this thread's counters.
pub(crate) fn reset() {
    HITS.with(|h| h.set([[0; N_BRANCH]; N_SITE]));
}

/// This thread's counters.
pub(crate) fn get() -> Counts {
    HITS.with(Cell::get)
}
