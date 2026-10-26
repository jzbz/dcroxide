// SPDX-License-Identifier: ISC
//! Every class of compact signature recovery (ER-*) against dcrd's own code
//! through the oracle, at its per-PR size: zero disagreements, and every
//! case's intent held.

mod common;

use dcroxide_sigdiff::class::Family;

#[test]
fn every_recovery_class_agrees_with_dcrd() {
    common::run_family(Family::Recover);
}
