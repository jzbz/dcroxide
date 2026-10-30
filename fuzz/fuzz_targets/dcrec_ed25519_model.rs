// SPDX-License-Identifier: ISC
//! Fuzz target for dcroxide-dcrec's Ed25519 against a model of dcrd's, with
//! no oracle: the first input byte picks one of dcroxide-sigdiff's Ed25519
//! classes (`fuzz::Target::Ed25519`, the table dcrec_diff_ed25519 reads),
//! the next eight the case index, and the rest is the class generator's
//! entropy.  Each request is answered by dcroxide-dcrec and by
//! dcroxide-sigdiff's model of dcrd's key and signature parsing and of
//! agl's verification, and a signature dcroxide makes must verify under
//! the model.  The classes build what keys from a seed never reach: the
//! eight small-order points and `a·B + T` keys at every residue, their
//! non-canonical encodings, and zero-S signatures with a small-order R
//! (ADR-0006's 2026-07-26 addendum).  The model decodes points with the
//! same curve25519-dalek decompression as dcroxide-dcrec, so decoding
//! itself is checked against dcrd by dcrec_diff_ed25519.  `sigsoak
//! fuzz-replay --target dcrec_ed25519_model` replays a crash input without
//! libFuzzer.

#![no_main]

use dcroxide_sigdiff::fuzz;
use dcroxide_sigdiff::run::ours_answerer;
use libfuzzer_sys::{Corpus, fuzz_target};

fuzz_target!(
    init: fuzz::install_panic_context(),
    |data: &[u8]| -> Corpus {
        if fuzz::fuzz_ed25519_model(data, &ours_answerer(None)) {
            Corpus::Keep
        } else {
            Corpus::Reject
        }
    }
);
