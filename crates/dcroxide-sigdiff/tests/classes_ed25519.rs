// SPDX-License-Identifier: ISC
//! Every class of Ed25519 signing, key and signature parsing and raw
//! verification (DS-*, DK-*, DG-*, DV-*) against dcrd's own code through
//! the oracle, at its per-PR size: zero disagreements, error texts
//! included, and every case's intent held.

mod common;

use dcroxide_sigdiff::class::Family;

#[test]
fn every_ed25519_class_agrees_with_dcrd() {
    common::run_family(Family::Ed25519);
}
